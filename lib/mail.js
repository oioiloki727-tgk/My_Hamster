'use strict';
// Отправка писем без внешних зависимостей.
// Режимы (выбираются автоматически по .env):
//   resend  — если задан RESEND_API_KEY
//   smtp    — если задан SMTP_HOST
//   console — иначе: ссылка просто печатается в консоль сервера (для разработки)

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const env = () => process.env;
const mode = () => (env().RESEND_API_KEY ? 'resend' : env().SMTP_HOST ? 'smtp' : 'console');
const FROM = () => env().MAIL_FROM || 'Мой хомячок <noreply@localhost>';

const b64 = s => Buffer.from(s, 'utf8').toString('base64');
const wrap76 = s => s.replace(/.{76}/g, '$&\r\n');
const encWord = s => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`);
const bareAddr = s => ((s.match(/<([^>]+)>/) || [null, s])[1] || '').trim();
const noCRLF = s => String(s).replace(/[\r\n]+/g, ' ');

function fromHeader(from) {
  const m = from.match(/^(.*)<(.+)>\s*$/);
  if (!m) return noCRLF(from);
  const name = m[1].trim().replace(/^"|"$/g, '');
  return name ? `${encWord(noCRLF(name))} <${noCRLF(m[2].trim())}>` : `<${noCRLF(m[2].trim())}>`;
}

function buildMime({ from, to, subject, text, html }) {
  const boundary = 'b_' + crypto.randomBytes(12).toString('hex');
  const domain = (bareAddr(from).split('@')[1] || 'localhost').replace(/[^a-z0-9.\-]/gi, '');
  const part = (type, body) =>
    `--${boundary}\r\nContent-Type: ${type}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${wrap76(b64(body))}\r\n`;
  return [
    `From: ${fromHeader(from)}`,
    `To: <${noCRLF(to)}>`,
    `Subject: ${encWord(noCRLF(subject))}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomBytes(12).toString('hex')}@${domain}>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    part('text/plain', text) + part('text/html', html) + `--${boundary}--`,
    ''
  ].join('\r\n');
}

// ---------- минимальный SMTP-клиент ----------
function makeConn(sock) {
  const o = { sock, buf: '', q: [], err: null };
  const take = () => {
    const lines = o.buf.split('\r\n'); // последний элемент — неполная строка
    for (let i = 0; i < lines.length - 1; i++) {
      if (/^\d{3}( |$)/.test(lines[i])) {
        const resp = lines.slice(0, i + 1);
        o.buf = lines.slice(i + 1).join('\r\n');
        return { code: +resp[0].slice(0, 3), text: resp.join('\n') };
      }
    }
    return null;
  };
  const flush = () => {
    while (o.q.length) {
      const r = take();
      if (r) o.q.shift().res(r);
      else if (o.err) o.q.shift().rej(o.err);
      else break;
    }
  };
  sock.on('data', d => { o.buf += d.toString('utf8'); flush(); });
  sock.on('error', e => { o.err = e; flush(); });
  sock.on('close', () => { if (!o.err) o.err = new Error('SMTP: соединение закрыто'); flush(); });
  o.read = () => new Promise((res, rej) => { o.q.push({ res, rej }); flush(); });
  o.write = s => sock.write(s);
  return o;
}

async function smtpSend({ host, port, secure, user, pass }, { from, to, raw }) {
  const timeout = s => s.setTimeout(20000, () => s.destroy(new Error('SMTP: таймаут')));
  const first = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
  timeout(first);
  let c = makeConn(first);
  const expect = async codes => {
    const r = await c.read();
    if (!codes.includes(r.code)) throw new Error('SMTP: ' + r.text);
    return r;
  };
  const cmd = async (line, codes) => { c.write(line + '\r\n'); return expect(codes); };
  try {
    await expect([220]);
    let r = await cmd('EHLO hamster.local', [250]);
    let isTls = !!secure;
    if (!isTls && /STARTTLS/i.test(r.text)) {
      await cmd('STARTTLS', [220]);
      c.sock.removeAllListeners('data');
      const s2 = tls.connect({ socket: c.sock, servername: host });
      timeout(s2);
      c = makeConn(s2);
      isTls = true;
      r = await cmd('EHLO hamster.local', [250]);
    }
    if (user) {
      if (!isTls) throw new Error('SMTP: сервер не поддерживает TLS, пароль не отправляю');
      await cmd('AUTH LOGIN', [334]);
      await cmd(b64(user), [334]);
      await cmd(b64(pass || ''), [235]);
    }
    await cmd(`MAIL FROM:<${bareAddr(from)}>`, [250]);
    await cmd(`RCPT TO:<${to}>`, [250, 251]);
    await cmd('DATA', [354]);
    const body = raw.split('\r\n').map(l => (l.startsWith('.') ? '.' + l : l)).join('\r\n');
    c.write(body + '\r\n.\r\n');
    await expect([250]);
    try { c.write('QUIT\r\n'); } catch (e) {}
  } finally {
    c.sock.end();
  }
}

// ---------- публичный API ----------
async function sendMail({ to, subject, text, html }) {
  const m = mode();
  if (m === 'console') {
    console.log('\n──────── ПИСЬМО (режим консоли: почта не настроена) ────────');
    console.log('Кому:', to, '\nТема:', subject, '\n\n' + text);
    console.log('────────────────────────────────────────────────────────────\n');
    return;
  }
  if (m === 'resend') {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + env().RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: FROM(), to: [to], subject, text, html })
    });
    if (!r.ok) throw new Error('Resend ' + r.status + ': ' + (await r.text()).slice(0, 300));
    return;
  }
  const port = +env().SMTP_PORT || 465;
  const secure = env().SMTP_SECURE ? env().SMTP_SECURE === 'true' : port === 465;
  await smtpSend(
    { host: env().SMTP_HOST, port, secure, user: env().SMTP_USER, pass: env().SMTP_PASS },
    { from: FROM(), to, raw: buildMime({ from: FROM(), to, subject, text, html }) }
  );
}

module.exports = { sendMail, mode };

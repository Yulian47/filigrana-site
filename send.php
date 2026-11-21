<?php
// Filigrana Digital — kontaktskjema. Sender e-post via PHP mail() på Simply.com.
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
const TO = 'post@filigranadigital.no';
const FROM = 'post@filigranadigital.no';
const HOSTS = ['filigranadigital.no', 'www.filigranadigital.no'];

function out(int $code, bool $ok): never { http_response_code($code); echo json_encode(['ok' => $ok]); exit; }
function clean(string $s, int $max): string { $s = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $s)); return mb_substr($s, 0, $max); }
function line(string $s): string { return trim(preg_replace('/[\r\n]+/', ' ', $s)); }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(405, false);
$o = parse_url($_SERVER['HTTP_ORIGIN'] ?? '', PHP_URL_HOST);
if ($o !== null && $o !== false && !in_array($o, HOSTS, true)) out(403, false);

$d = json_decode(file_get_contents('php://input', false, null, 0, 20000) ?: '', true);
if (!is_array($d)) out(400, false);
if (!empty($d['website'])) out(200, true); // honeypot: late som om det gikk bra

$name = line(clean((string)($d['name'] ?? ''), 120));
$email = line(clean((string)($d['email'] ?? ''), 160));
$subject = line(clean((string)($d['subject'] ?? 'Ny prosjektforespørsel'), 160));
$body = clean((string)($d['body'] ?? ''), 4000);
if ($name === '' || $body === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) out(422, false);

// enkel rate limit: 1 forespørsel per 20 sek per IP
$f = sys_get_temp_dir() . '/fg_rl_' . sha1($_SERVER['REMOTE_ADDR'] ?? '');
if (is_file($f) && time() - filemtime($f) < 20) out(429, false);
@touch($f);

$headers = [
  'From: Filigrana Digital <' . FROM . '>',
  'Reply-To: ' . $name . ' <' . $email . '>',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=UTF-8',
  'X-Mailer: filigranadigital.no',
];
$ok = mail(TO, mb_encode_mimeheader($subject, 'UTF-8', 'B', "\r\n"), $body, implode("\r\n", $headers), '-f' . FROM);
out($ok ? 200 : 500, $ok);

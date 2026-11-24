/* معمل الأمن التفاعلي — core: pure logic (no DOM, testable in node)
   Caesar cipher, password strength model, phishing game data */
(function (global) {
'use strict';

/* ================= Caesar cipher ================= */
function caesarShiftChar(ch, shift) {
  var c = ch.charCodeAt(0);
  if (c >= 65 && c <= 90) return String.fromCharCode(65 + ((c - 65 + shift) % 26 + 26) % 26);
  if (c >= 97 && c <= 122) return String.fromCharCode(97 + ((c - 97 + shift) % 26 + 26) % 26);
  return ch;
}
function caesar(text, shift) {
  var out = '';
  for (var i = 0; i < text.length; i++) out += caesarShiftChar(text[i], shift);
  return out;
}
function caesarDecrypt(text, shift) { return caesar(text, 26 - (shift % 26)); }

/* ================= Password strength model =================
   Model (documented, deterministic):
   - pool = size of character set actually used:
     lowercase 26 + uppercase 26 + digits 10 + symbols 33
   - combinations = pool ^ length
   - attacker speed = 10 billion guesses/sec (10^10), offline attack on a fast hash
   - average crack time = combinations / (2 * speed)
   Common passwords and trivial patterns collapse to 'instant'. */
var GUESSES_PER_SEC = 1e10;

var COMMON_PASSWORDS = [
  '123456', 'password', '123456789', '12345', '12345678', 'qwerty', '1234567',
  '111111', '1234567890', '123123', 'abc123', '1234', 'password1', 'iloveyou',
  '1q2w3e4r', '000000', 'qwerty123', 'zaq12wsx', 'dragon', 'sunshine',
  'princess', 'letmein', '654321', 'monkey', '27653', '1qaz2wsx', '123321',
  'qwertyuiop', 'superman', 'asdfghjkl', 'ahmed123', '010101'
];

function passwordPool(pw) {
  var pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return pool;
}

function isCommonPassword(pw) {
  var low = pw.toLowerCase();
  for (var i = 0; i < COMMON_PASSWORDS.length; i++) {
    if (low === COMMON_PASSWORDS[i]) return true;
  }
  return false;
}

/* seconds to crack on average; Infinity-safe via log math */
function crackSeconds(pw) {
  if (!pw) return 0;
  if (isCommonPassword(pw)) return 0.05; /* first guesses */
  var pool = passwordPool(pw);
  if (pool === 0) return 0;
  var logCombos = pw.length * Math.log10(pool);
  var logAvg = logCombos - Math.log10(2 * GUESSES_PER_SEC);
  if (logAvg < 15) return Math.pow(10, logAvg);
  return { log10: logAvg }; /* too big for a double to be meaningful */
}

/* human-readable Arabic duration from crackSeconds result */
function humanizeCrack(res) {
  if (typeof res === 'object') {
    var yearsLog = res.log10 - Math.log10(31557600);
    if (yearsLog >= 12) return 'تريليونات السنين';
    if (yearsLog >= 9) return 'مليارات السنين';
    if (yearsLog >= 6) return 'ملايين السنين';
    return 'آلاف السنين';
  }
  var s = res;
  if (s < 1) return 'لحظياً (أقل من ثانية)';
  if (s < 60) return Math.round(s) + ' ثانية تقريباً';
  var m = s / 60;
  if (m < 60) return 'حوالي ' + roundNice(m) + ' دقيقة';
  var h = m / 60;
  if (h < 24) return 'حوالي ' + roundNice(h) + ' ساعة';
  var d = h / 24;
  if (d < 30) return 'حوالي ' + roundNice(d) + ' يوم';
  var mo = d / 30;
  if (mo < 12) return 'حوالي ' + roundNice(mo) + ' شهر';
  var y = d / 365.25;
  if (y < 1000) return 'حوالي ' + roundNice(y) + ' سنة';
  if (y < 1e6) return 'آلاف السنين';
  if (y < 1e9) return 'ملايين السنين';
  if (y < 1e12) return 'مليارات السنين';
  return 'تريليونات السنين';
}

function roundNice(x) {
  if (x >= 100) return Math.round(x).toLocaleString('en-US');
  if (x >= 10) return String(Math.round(x));
  return (Math.round(x * 10) / 10).toString();
}

/* score 0..4 + checklist for the UI */
function analyzePassword(pw) {
  var checks = [
    { id: 'len12', label: '12 حرف أو أكتر', ok: pw.length >= 12 },
    { id: 'lower', label: 'حروف صغيرة (a-z)', ok: /[a-z]/.test(pw) },
    { id: 'upper', label: 'حروف كبيرة (A-Z)', ok: /[A-Z]/.test(pw) },
    { id: 'digit', label: 'أرقام (0-9)', ok: /[0-9]/.test(pw) },
    { id: 'symbol', label: 'رموز (!@#$...)', ok: /[^a-zA-Z0-9]/.test(pw) },
    { id: 'notcommon', label: 'مش من الباسوردات الشائعة', ok: pw.length > 0 && !isCommonPassword(pw) }
  ];
  var okCount = 0;
  checks.forEach(function (c) { if (c.ok) okCount++; });
  var score;
  if (pw.length === 0) score = 0;
  else if (isCommonPassword(pw)) score = 0;
  else if (pw.length < 8) score = 1;
  else if (okCount <= 3) score = 1;
  else if (okCount === 4) score = 2;
  else if (okCount === 5) score = 3;
  else score = 4;
  var labels = ['ضعيفة جداً', 'ضعيفة', 'وسط', 'قوية', 'قوية جداً'];
  return {
    score: pw.length === 0 ? -1 : score,
    label: pw.length === 0 ? '' : labels[score],
    checks: checks,
    crack: pw.length === 0 ? '' : humanizeCrack(crackSeconds(pw)),
    pool: pw.length === 0 ? 0 : passwordPool(pw),
    combosLog10: pw.length === 0 ? 0 : pw.length * Math.log10(passwordPool(pw))
  };
}

/* ================= Cipher challenges (answers verified by node tests) ================= */
var CIPHER_CHALLENGES = [
  { id: 1, hint: 'مستوى سهل: كلمة إنجليزية من 5 حروف معناها "أهلاً"', answer: 'HELLO' },
  { id: 2, hint: 'كلمة من 8 حروف معناها "الأمان"', answer: 'SECURITY' },
  { id: 3, hint: 'كلمة من 6 حروف معناها "هجوم"', answer: 'ATTACK' },
  { id: 4, hint: 'كلمة من 7 حروف معناها "الدفاع"', answer: 'DEFENSE' },
  { id: 5, hint: 'كلمة من 6 حروف معناها "مخترق"', answer: 'HACKER' }
];
/* deterministic shifts per challenge */
var CHALLENGE_SHIFTS = [3, 5, 7, 11, 13];
CIPHER_CHALLENGES.forEach(function (c, i) {
  c.shift = CHALLENGE_SHIFTS[i];
  c.cipher = caesar(c.answer, c.shift);
});

/* ================= Spot-the-phishing game =================
   All scenarios are fictional, written for training. */
var PHISH_CARDS = [
  {
    kind: 'إيميل',
    from: 'Egypt Post <no-reply@egyptp0st-deliver.com>',
    subject: 'طردك متوقف في الجمارك!',
    body: 'عميلنا العزيز، طردك متوقف ولن يتم تسليمه حتى يتم سداد رسوم التخليص 47 جنيه خلال 24 ساعة وإلا سيتم إعادة الطرد. ادفع الآن من الرابط: http://egyptp0st-deliver.com/pay',
    phishing: true,
    flags: ['رقم صفر بدل حرف o في الدومين (egyptp0st)', 'استعجال وتهديد بإعادة الطرد', 'طلب فلوس عن طريق لينك http مش رسمي']
  },
  {
    kind: 'إيميل',
    from: 'GitHub <noreply@github.com>',
    subject: '[GitHub] Your password was changed',
    body: 'Hi Ahmed, your GitHub account password was recently changed. If this was you, you can safely ignore this email. If you did not change your password, visit github.com and secure your account from Settings.',
    phishing: false,
    flags: ['دومين رسمي github.com', 'مفيش استعجال ولا طلب فلوس', 'بيوجهك تدخل الموقع الرسمي بنفسك بدل ما يديك لينك مختصر']
  },
  {
    kind: 'رسالة SMS',
    from: 'VODAFONE-CASH',
    body: 'مبروك! كسبت 50,000 جنيه في سحب فودافون كاش. لتأكيد الاستلام ابعت رقم المحفظة والرقم السري على الرقم ده قبل نص الليل.',
    phishing: true,
    flags: ['جايزة من غير ما تشترك في سحب أصلاً', 'أي خدمة حقيقية مستحيل تطلب الرقم السري', 'استعجال: "قبل نص الليل"']
  },
  {
    kind: 'رسالة واتساب',
    from: '+44 7700 900123 (رقم غير معروف)',
    body: 'أهلاً يا حبيبي أنا صاحبك، موبايلي اتكسر وبكلمك من الرقم ده. محتاج منك خدمة عاجلة: حوّلي 2000 جنيه على المحفظة دي 010xxxx وأنا هردهالك بكرة.',
    phishing: true,
    flags: ['رقم دولي غريب بيدّعي إنه صاحبك', 'قصة عاجلة + طلب فلوس', 'الحل: كلم صاحبك على رقمه القديم واتأكد بنفسك']
  },
  {
    kind: 'إيميل',
    from: 'Microsoft Account Team <account-security-noreply@accountprotection.microsoft.com>',
    subject: 'Microsoft account security info was added',
    body: 'Security info was added to your Microsoft account. If this was you, no action is needed. If not, go to account.microsoft.com and review your security settings.',
    phishing: false,
    flags: ['دومين فرعي حقيقي تابع لـ microsoft.com', 'إشعار معلوماتي مش طلب فوري', 'بيطلب منك تدخل الموقع الرسمي بنفسك']
  },
  {
    kind: 'إيميل',
    from: 'IT Support <it.support@uni-cairo-edu-eg.com>',
    subject: 'URGENT: Your university email will be suspended',
    body: 'Dear Student, your mailbox exceeded its quota. Verify within 12 hours by sending your username and password to this email, otherwise your account will be deleted permanently.',
    phishing: true,
    flags: ['دومين مفبرك بيقلد الجامعة (uni-cairo-edu-eg.com)', 'الدعم الحقيقي مستحيل يطلب الباسورد في إيميل', 'تهديد بحذف الحساب + مهلة قصيرة']
  },
  {
    kind: 'رسالة SMS',
    from: 'EG-BANK',
    body: 'تنبيه أمني: تم تسجيل الدخول لحسابك من جهاز جديد. إذا لم تكن أنت، اتصل بخدمة العملاء على الرقم المكتوب خلف بطاقتك البنكية.',
    phishing: false,
    flags: ['مفيش لينك ولا طلب بيانات', 'بيوجهك لرقم خدمة العملاء الرسمي المكتوب على البطاقة', 'ده سلوك بنوك حقيقي فعلاً']
  },
  {
    kind: 'إيميل',
    from: 'Netflix <support@netflix-billing-update.net>',
    subject: 'تم رفض عملية الدفع - حدّث بياناتك الآن',
    body: 'عزيزي المشترك، فشل خصم اشتراكك الشهري. حدّث بيانات بطاقتك خلال 48 ساعة وإلا سيتم إيقاف حسابك. اضغط هنا: http://netflix-billing-update.net/eg/update',
    phishing: true,
    flags: ['الدومين نهايته .net ومصمم يشبه netflix.com', 'طلب بيانات بطاقة من لينك في إيميل', 'ضغط زمني: "خلال 48 ساعة"']
  }
];

/* meta for hero stats (computed, not hardcoded) */
var CYBER_LAB_META = {
  challenges: CIPHER_CHALLENGES.length + PHISH_CARDS.length,
  cipherChallenges: CIPHER_CHALLENGES.length,
  phishingCards: PHISH_CARDS.length
};

var API = {
  caesar: caesar,
  caesarDecrypt: caesarDecrypt,
  analyzePassword: analyzePassword,
  crackSeconds: crackSeconds,
  humanizeCrack: humanizeCrack,
  isCommonPassword: isCommonPassword,
  passwordPool: passwordPool,
  CIPHER_CHALLENGES: CIPHER_CHALLENGES,
  PHISH_CARDS: PHISH_CARDS,
  CYBER_LAB_META: CYBER_LAB_META
};

global.CYBER_CORE = API;
global.CYBER_LAB_META = CYBER_LAB_META;

})(typeof window !== 'undefined' ? window : globalThis);

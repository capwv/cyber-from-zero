/* معمل الأمن التفاعلي — UI: Caesar tool, cipher challenges, password meter, phishing game */
(function () {
'use strict';
var C = window.CYBER_CORE;

function el(id) { return document.getElementById(id); }
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ============ 1) Caesar tool ============ */
var shiftRange = el('caesar-shift');
var shiftVal = el('caesar-shift-val');
shiftRange.addEventListener('input', function () { shiftVal.textContent = shiftRange.value; });

function runCaesar(decrypt) {
  var text = el('caesar-in').value;
  var shift = parseInt(shiftRange.value, 10);
  var out = decrypt ? C.caesarDecrypt(text, shift) : C.caesar(text, shift);
  el('caesar-out').textContent = out || '—';
}
el('caesar-enc').addEventListener('click', function () { runCaesar(false); });
el('caesar-dec').addEventListener('click', function () { runCaesar(true); });

/* ============ 2) Cipher challenges ============ */
var chHost = el('cipher-challenges');
C.CIPHER_CHALLENGES.forEach(function (ch) {
  var box = document.createElement('div');
  box.className = 'challenge';
  box.innerHTML =
    '<div class="ch-head"><span class="ch-num">تحدي ' + ch.id + '</span><span class="ch-cipher mono" dir="ltr">' + esc(ch.cipher) + '</span></div>' +
    '<p class="small">' + esc(ch.hint) + '</p>' +
    '<div class="ch-row">' +
      '<input class="ch-answer" dir="ltr" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="النص بعد فك التشفير" aria-label="إجابة التحدي ' + ch.id + '">' +
      '<button class="cta ch-check">تحقق</button>' +
    '</div>' +
    '<div class="ch-fb"></div>';
  var input = box.querySelector('.ch-answer');
  var btn = box.querySelector('.ch-check');
  var fb = box.querySelector('.ch-fb');
  function check() {
    var val = input.value.trim().toUpperCase();
    if (!val) { fb.className = 'ch-fb no'; fb.textContent = 'اكتب إجابتك الأول.'; return; }
    if (val === ch.answer) {
      box.classList.add('done');
      fb.className = 'ch-fb ok';
      fb.textContent = '✅ صح! النص الأصلي هو ' + ch.answer + ' والإزاحة كانت ' + ch.shift + '.';
      input.disabled = true; btn.disabled = true;
      refreshMissions();
    } else {
      fb.className = 'ch-fb no';
      fb.textContent = '❌ لسه. جرب إزاحات مختلفة في الآلة فوق لحد ما يطلع نص له معنى.';
    }
  }
  btn.addEventListener('click', check);
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter') check(); });
  chHost.appendChild(box);
});

/* ============ 3) Password strength tester ============ */
var pwIn = el('pw-in');
var meterColors = ['#ff6b6b', '#ff6b6b', '#ffc048', '#4da3ff', '#2ecc71'];
pwIn.addEventListener('input', function () {
  var a = C.analyzePassword(pwIn.value);
  var fill = el('pw-fill');
  var labelEl = el('pw-label');
  var crackEl = el('pw-crack');
  var checksEl = el('pw-checks');
  if (a.score < 0) {
    fill.style.width = '0%';
    labelEl.textContent = '';
    crackEl.textContent = '';
    checksEl.innerHTML = '';
    return;
  }
  fill.style.width = ((a.score + 1) * 20) + '%';
  fill.style.background = meterColors[a.score];
  labelEl.textContent = 'القوة: ' + a.label;
  labelEl.style.color = meterColors[a.score];
  crackEl.innerHTML = 'وقت التخمين التقريبي (هجوم offline بسرعة 10 مليار محاولة/ثانية): <b>' + esc(a.crack) + '</b>';
  checksEl.innerHTML = a.checks.map(function (c) {
    return '<li class="' + (c.ok ? 'ok' : 'no') + '">' + (c.ok ? '✓ ' : '✗ ') + esc(c.label) + '</li>';
  }).join('');
});

/* ============ 4) Spot-the-phishing game ============ */
var phishIdx = 0, phishScore = 0, phishAnswered = false;

function renderPhishCard() {
  var host = el('phish-card');
  var scoreEl = el('phish-score');
  if (phishIdx >= C.PHISH_CARDS.length) {
    host.innerHTML =
      '<div class="phish-end">' +
      '<div class="phish-final">' + phishScore + ' / ' + C.PHISH_CARDS.length + '</div>' +
      '<p>' + (phishScore === C.PHISH_CARDS.length
        ? '🏆 نتيجة كاملة! عينك اتدربت على العلامات الحمرا. خليها صاحية في كل رسالة جديدة.'
        : phishScore >= C.PHISH_CARDS.length - 2
          ? '👏 قريب جداً! راجع الرسايل اللي غلطت فيها وشوف العلامات اللي فاتتك.'
          : '💪 بداية كويسة، بس محتاج تدريب أكتر. أعد اللعبة وركز في الاستعجال والدومينات وطلبات البيانات.') + '</p>' +
      '<button class="cta" id="phish-restart">العب تاني</button></div>';
    el('phish-restart').addEventListener('click', function () {
      phishIdx = 0; phishScore = 0; renderPhishCard(); refreshMissions();
    });
    scoreEl.textContent = '';
    refreshMissions();
    return;
  }
  var card = C.PHISH_CARDS[phishIdx];
  phishAnswered = false;
  host.innerHTML =
    '<div class="phish-progress">رسالة ' + (phishIdx + 1) + ' من ' + C.PHISH_CARDS.length + '</div>' +
    '<div class="phish-msg">' +
      '<div class="phish-kind">' + esc(card.kind) + '</div>' +
      '<div class="phish-from" dir="ltr">' + esc(card.from) + '</div>' +
      (card.subject ? '<div class="phish-subject">' + esc(card.subject) + '</div>' : '') +
      '<div class="phish-body">' + esc(card.body) + '</div>' +
    '</div>' +
    '<div class="phish-btns">' +
      '<button class="cta" id="phish-safe">✅ رسالة آمنة</button>' +
      '<button class="cta phish-danger" id="phish-bad">🚨 Phishing</button>' +
    '</div>' +
    '<div class="phish-fb"></div>';
  scoreEl.textContent = 'النتيجة: ' + phishScore + ' / ' + phishIdx;

  function answer(userSaysPhish) {
    if (phishAnswered) return;
    phishAnswered = true;
    var correct = (userSaysPhish === card.phishing);
    if (correct) phishScore++;
    var fb = host.querySelector('.phish-fb');
    fb.className = 'phish-fb ' + (correct ? 'ok' : 'no');
    fb.innerHTML =
      '<div class="phish-verdict">' + (correct ? '✅ إجابة صحيحة! ' : '❌ إجابة غلط. ') +
      (card.phishing ? 'الرسالة دي فخ phishing.' : 'الرسالة دي آمنة فعلاً.') + '</div>' +
      '<ul class="phish-flags">' + card.flags.map(function (f) { return '<li>' + esc(f) + '</li>'; }).join('') + '</ul>' +
      '<button class="cta" id="phish-next">' + (phishIdx + 1 >= C.PHISH_CARDS.length ? 'شوف النتيجة النهائية' : 'الرسالة اللي بعدها') + '</button>';
    host.querySelector('#phish-next').addEventListener('click', function () {
      phishIdx++;
      renderPhishCard();
      refreshMissions();
    });
    scoreEl.textContent = 'النتيجة: ' + phishScore + ' / ' + (phishIdx + 1);
    refreshMissions();
  }
  el('phish-safe').addEventListener('click', function () { answer(false); });
  el('phish-bad').addEventListener('click', function () { answer(true); });
}
renderPhishCard();

/* ============ missions panel + reset ============ */
function refreshMissions() {
  var panel = el('missions-panel');
  if (panel.hidden) return;
  var doneCh = document.querySelectorAll('#cipher-challenges .challenge.done').length;
  var html = '<div class="mission' + (doneCh === C.CIPHER_CHALLENGES.length ? ' done' : '') + '">' +
    '<div class="m-title"><span class="m-check">' + (doneCh === C.CIPHER_CHALLENGES.length ? '✓' : '') + '</span> تحديات فك الشفرة</div>' +
    '<p>حليت ' + doneCh + ' من ' + C.CIPHER_CHALLENGES.length + ' تحديات قيصر.</p></div>';
  html += '<div class="mission' + (phishIdx >= C.PHISH_CARDS.length ? ' done' : '') + '">' +
    '<div class="m-title"><span class="m-check">' + (phishIdx >= C.PHISH_CARDS.length ? '✓' : '') + '</span> لعبة اصطاد الـ Phishing</div>' +
    '<p>' + (phishIdx >= C.PHISH_CARDS.length
      ? 'خلصت اللعبة بنتيجة ' + phishScore + ' من ' + C.PHISH_CARDS.length + '.'
      : 'لسه بتلعب: وصلت للرسالة ' + (phishIdx + 1) + ' من ' + C.PHISH_CARDS.length + '.') + '</p></div>';
  html += '<div class="mission"><div class="m-title"><span class="m-check"></span> مقياس الباسورد</div>' +
    '<p>جرب توصل لباسورد "قوية جداً" من عندك: 12+ حرف، كل أنواع الرموز، ومش شائع.</p></div>';
  panel.innerHTML = html;
}

el('missions-toggle').addEventListener('click', function () {
  var panel = el('missions-panel');
  panel.hidden = !panel.hidden;
  refreshMissions();
});

el('reset-lab').addEventListener('click', function () {
  if (!confirm('تصفّر المعمل كله؟ (تحديات قيصر ولعبة الـ phishing هترجع من الأول)')) return;
  el('caesar-in').value = '';
  el('caesar-out').textContent = '—';
  pwIn.value = '';
  pwIn.dispatchEvent(new Event('input'));
  document.querySelectorAll('#cipher-challenges .challenge').forEach(function (box) {
    box.classList.remove('done');
    var input = box.querySelector('.ch-answer');
    input.disabled = false; input.value = '';
    box.querySelector('.ch-check').disabled = false;
    box.querySelector('.ch-fb').textContent = '';
  });
  phishIdx = 0; phishScore = 0;
  renderPhishCard();
  refreshMissions();
});

window.CYBER_LAB_FOCUS = function () { el('caesar-in').focus(); };
})();

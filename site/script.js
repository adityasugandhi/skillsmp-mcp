// Theme toggle
function toggleTheme() {
  var html = document.documentElement;
  var current = html.getAttribute('data-theme');
  var next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  var btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = next === 'dark' ? 'Light' : 'Dark';
}

// Copy install command
function copyInstall() {
  var text = document.getElementById('install-cmd').textContent;
  var btn = document.getElementById('copy-btn');
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
  }).catch(function() {
    // Fallback for older browsers
    var textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
  });
}

// Wire up on DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
  // Theme button
  var themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    var current = document.documentElement.getAttribute('data-theme');
    themeBtn.textContent = current === 'dark' ? 'Light' : 'Dark';
    themeBtn.addEventListener('click', toggleTheme);
  }

  // Copy button
  var copyBtn = document.getElementById('copy-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', copyInstall);
  }
});

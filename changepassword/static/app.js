// SPDX-License-Identifier: GPL-3.0-or-later
// changepassword's one script: copy the link, and select it on a click.
(function () {
  'use strict';
  var link = document.getElementById('link');
  var copy = document.getElementById('copy');
  var copied = document.getElementById('copied');
  if (!link) { return; }
  link.addEventListener('focus', function () { link.select(); });
  if (!copy || !navigator.clipboard) { if (copy) { copy.hidden = true; } return; }
  copy.addEventListener('click', function () {
    navigator.clipboard.writeText(link.value).then(function () {
      copied.hidden = false;
    }, function () {
      link.select();
    });
  });
}());

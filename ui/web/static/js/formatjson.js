// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

function syntaxHighlight(json) {
  json = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return json.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    function (match) {
      var cls = "number";
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = "key";
        } else {
          cls = "string";
        }
      } else if (/true|false/.test(match)) {
        cls = "boolean";
      } else if (/null/.test(match)) {
        cls = "null";
      }
      return '<span class="' + cls + '">' + match + "</span>";
    },
  );
}

function attachFormatJsonWithPrettifyListener(config) {
  document.addEventListener("DOMContentLoaded", function () {
    var meta = JSON.parse(config.data);
    document.getElementById(config.id).innerHTML = syntaxHighlight(JSON.stringify(meta, null, 2));
  });
}

function codeMirrorEditor(config) {
  var editor = CodeMirror.fromTextArea(document.getElementById(config.textArea), {
    mode: "application/json",
    matchBrackets: true,
    autoCloseBrackets: true,
    lineWrapping: true,
    lineNumbers: true,
    lint: true,
    gutters: ["CodeMirror-lint-markers"],
    autoRefresh: true,
  });
  editor.setValue(JSON.stringify(config.value, null, 2));
  editor.setSize("100%", 200);
  document.getElementById(config.button).addEventListener("click", function () {
    document.getElementById(config.textArea).value = editor.getValue();
  });
}

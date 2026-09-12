// content.js — injected only after the user opens Blindspot on the current tab.
// It extracts page text and hidden attack surfaces; scanning remains local.

(function installBlindspotExtractor() {
  'use strict';

  // executeScript may run this file again for a rescan. Keep exactly one listener
  // in the page's isolated extension world.
  if (globalThis.__blindspotExtractorInstalled) return;
  Object.defineProperty(globalThis, '__blindspotExtractorInstalled', { value: true });

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== 'BLINDSPOT_SCAN_PAGE') return false;
    sendResponse({
      extracted: extractContent(),
      surfaces: extractWebPageAttackSurfaces(),
    });
    return false;
  });

  const MAX_CONTENT_CHARS = 80000;
  const MAX_HIDDEN_SURFACES = 40;
  const MAX_ATTACK_SURFACES = 100;
  const INVISIBLE_RE = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060-\u2064\u202A-\u202E\u2066-\u2069]/;

  function extractWebPageAttackSurfaces() {
    const surfaces = [];
    const pushIfMeaningful = (surface, text) => {
      const trimmed = (text || '').trim();
      if (trimmed.length >= 8 && surfaces.length < MAX_ATTACK_SURFACES) {
        surfaces.push({ surface, text: trimmed.slice(0, 4000) });
      }
    };

    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) pushIfMeaningful('meta.description', metaDesc.getAttribute('content'));
    const metaKeywords = document.querySelector('meta[name="keywords"]');
    if (metaKeywords) pushIfMeaningful('meta.keywords', metaKeywords.getAttribute('content'));

    document.querySelectorAll('script[type="application/ld+json"]').forEach((element, index) => {
      pushIfMeaningful(`script[type=application/ld+json]#${index}`, element.textContent);
    });

    const commentWalker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let commentNode;
    let commentIndex = 0;
    while ((commentNode = commentWalker.nextNode())) {
      pushIfMeaningful(`html-comment#${commentIndex++}`, commentNode.data);
      if (commentIndex >= MAX_HIDDEN_SURFACES) break;
    }

    let hiddenCount = 0;
    for (const element of document.querySelectorAll('body *')) {
      if (hiddenCount >= MAX_HIDDEN_SURFACES) break;
      if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(element.tagName)) continue;
      const text = element.textContent;
      if (!text || text.trim().length < 8 || !isHiddenElement(element)) continue;
      pushIfMeaningful(`hidden-text[${element.tagName.toLowerCase()}]`, text);
      hiddenCount += 1;
    }

    let invisibleTextCount = 0;
    const textWalker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
    );
    let textNode;
    while ((textNode = textWalker.nextNode())) {
      if (invisibleTextCount >= MAX_HIDDEN_SURFACES) break;
      const text = textNode.nodeValue || '';
      if (!INVISIBLE_RE.test(text)) continue;
      const parent = textNode.parentElement;
      if (!parent || ['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(parent.tagName)) continue;
      if (isHiddenElement(parent)) continue;
      pushIfMeaningful(`visible-text[invisible-unicode]#${invisibleTextCount++}`, text);
    }

    document.querySelectorAll('img[alt]').forEach((element) => {
      pushIfMeaningful('img[alt]', element.getAttribute('alt'));
    });
    document.querySelectorAll('a[title], button[title], img[title]').forEach((element) => {
      pushIfMeaningful(`${element.tagName.toLowerCase()}[title]`, element.getAttribute('title'));
    });
    return surfaces;
  }

  function isHiddenElement(element) {
    let style;
    try {
      style = window.getComputedStyle(element);
    } catch (_error) {
      return false;
    }
    if (!style) return false;
    if (style.display === 'none' || style.visibility === 'hidden') return true;
    if (Number.parseFloat(style.opacity) === 0 || Number.parseFloat(style.fontSize) === 0) return true;
    return Boolean(
      style.color &&
      style.backgroundColor &&
      style.backgroundColor !== 'rgba(0, 0, 0, 0)' &&
      style.backgroundColor !== 'transparent' &&
      style.color === style.backgroundColor
    );
  }

  function extractContent() {
    const url = location.href;
    const selection = window.getSelection()?.toString().trim();
    if (selection && selection.length > 80) {
      return { content: selection.slice(0, MAX_CONTENT_CHARS), source: 'selected text', url };
    }

    if (location.hostname === 'github.com') {
      const githubContent = extractGitHub();
      if (githubContent) return { ...githubContent, url };
    }

    const bodyPre = document.querySelector('body > pre');
    if (bodyPre && bodyPre.textContent.length > 100) {
      return { content: bodyPre.textContent.slice(0, MAX_CONTENT_CHARS), source: 'raw file', url };
    }

    const codeBlocks = extractCodeBlocks();
    if (codeBlocks) return { ...codeBlocks, url };

    const editable = extractEditable();
    if (editable) return { ...editable, url };

    const text = document.body?.innerText?.trim() || '';
    if (text.length < 200) return null;
    return { content: text.slice(0, MAX_CONTENT_CHARS), source: 'page text', url };
  }

  function extractGitHub() {
    const lines = document.querySelectorAll('.blob-code-inner');
    if (lines.length > 0) {
      return {
        content: [...lines].map((element) => element.textContent).join('\n').slice(0, MAX_CONTENT_CHARS),
        source: 'GitHub file',
      };
    }
    const editor = document.querySelector('.cm-content, .CodeMirror-code');
    return editor ? { content: editor.textContent.slice(0, MAX_CONTENT_CHARS), source: 'GitHub editor' } : null;
  }

  function extractCodeBlocks() {
    const texts = [...document.querySelectorAll('pre code, pre, code')]
      .map((element) => element.textContent.trim())
      .filter((text) => text.length > 100);
    if (!texts.length) return null;
    return {
      content: texts.join('\n\n---\n\n').slice(0, MAX_CONTENT_CHARS),
      source: `${texts.length} code block(s)`,
    };
  }

  function extractEditable() {
    const textarea = document.querySelector('textarea');
    if (textarea && textarea.value.length > 80) {
      return { content: textarea.value.slice(0, MAX_CONTENT_CHARS), source: 'textarea' };
    }
    const editable = document.querySelector('[contenteditable="true"]');
    if (editable && editable.innerText.length > 80) {
      return { content: editable.innerText.slice(0, MAX_CONTENT_CHARS), source: 'editable area' };
    }
    return null;
  }
})();

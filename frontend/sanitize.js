/**
 * sanitize.js — Lightweight HTML sanitization for ProofOfClaw frontend.
 *
 * Provides two globals:
 *   pocSanitize(dirty)  — parse HTML and strip dangerous elements/attributes
 *   pocEsc(str)         — context-safe text escaping (replaces the old esc())
 *
 * No dependencies.  Uses the browser-native DOMParser API so the heavy
 * lifting is done by the engine's own HTML parser — we only walk the
 * resulting tree and remove anything that shouldn't be there.
 */
(function () {
  'use strict';

  /* ── Allow-lists ──────────────────────────────────────────────────── */

  var ALLOWED_TAGS = new Set([
    // text & formatting
    'b', 'i', 'em', 'strong', 'u', 's', 'small', 'sub', 'sup', 'mark',
    'span', 'div', 'p', 'br', 'hr', 'blockquote', 'pre', 'code',
    // headings
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    // lists
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    // tables
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'caption',
    'colgroup', 'col',
    // media (src is validated separately)
    'img', 'figure', 'figcaption', 'picture', 'source', 'video', 'audio',
    // interactive safe subset (input, textarea, select excluded — they enable
    // UI redressing / fake login form attacks in user-generated content)
    'a', 'button', 'label', 'option',
    // semantic / layout
    'nav', 'section', 'article', 'header', 'footer', 'aside', 'main',
    'details', 'summary', 'time',
  ]);

  var ALLOWED_ATTRS = new Set([
    'class', 'id', 'href', 'src', 'alt', 'title', 'style',
    'aria-label', 'aria-hidden', 'aria-current', 'aria-live',
    'aria-expanded', 'aria-controls', 'aria-describedby',
    'role',
    'type', 'placeholder', 'value', 'name', 'for',
    'target', 'rel',
    'colspan', 'rowspan',
    'draggable', 'tabindex',
    'disabled', 'checked', 'selected', 'readonly',
    'width', 'height',
    'loading', 'decoding',
  ]);

  /** data-* attributes are allowed as a family. */
  var DATA_ATTR_RE = /^data-/;

  /** Attributes whose values are URLs that could be dangerous. */
  var URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'poster']);

  /** Protocol allow-list for URL attributes. */
  var SAFE_URL_RE = /^(?:https?|mailto|tel|#):/i;

  /** Matches event-handler attributes (onclick, onerror, onload …). */
  var EVENT_ATTR_RE = /^on/i;

  /* ── Helpers ──────────────────────────────────────────────────────── */

  /**
   * Return true if `value` is a safe URL for use in href/src/etc.
   * Blocks javascript:, data: (except safe image types), vbscript:, etc.
   */
  function isSafeUrl(value) {
    if (typeof value !== 'string') return false;
    var trimmed = value.replace(/[\x00-\x1f\x7f]/g, '').trim();
    // Relative URLs / anchors / empty are fine
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('/') || trimmed.startsWith('./') || trimmed.startsWith('../')) {
      return true;
    }
    // Only allow explicit safe protocols
    if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(trimmed)) {
      return SAFE_URL_RE.test(trimmed);
    }
    // No protocol means relative — safe
    return true;
  }

  /**
   * Return true if `attrName` is allowed on the given tag.
   */
  function isAllowedAttr(attrName) {
    var lower = attrName.toLowerCase();
    if (EVENT_ATTR_RE.test(lower)) return false;
    if (ALLOWED_ATTRS.has(lower)) return true;
    if (DATA_ATTR_RE.test(lower)) return true;
    return false;
  }

  /* ── Tree Walker ──────────────────────────────────────────────────── */

  /**
   * Recursively sanitize a DOM node (in-place).
   * Dangerous nodes are removed; dangerous attributes are stripped.
   */
  function walkNode(node) {
    if (!node) return;

    // Work on a static snapshot of children so removals don't skip nodes
    var children = Array.prototype.slice.call(node.childNodes);

    for (var i = 0; i < children.length; i++) {
      var child = children[i];

      // Text / comment nodes are fine (comments will be stripped below)
      if (child.nodeType === 8 /* COMMENT_NODE */) {
        node.removeChild(child);
        continue;
      }

      if (child.nodeType !== 1 /* ELEMENT_NODE */) {
        continue;
      }

      var tag = child.nodeName.toLowerCase();

      // --- Dangerous tags: remove entirely (including children) ---
      if (!ALLOWED_TAGS.has(tag)) {
        // For certain tags the *contents* are also dangerous (script, style,
        // noscript, iframe, object, embed, applet, form, math, svg, template).
        // For others (e.g. a custom element wrapper) we could keep children,
        // but it is safer to always drop children of unknown tags.
        var TOXIC_TAGS = new Set([
          'script', 'style', 'noscript', 'iframe', 'object', 'embed',
          'applet', 'form', 'math', 'svg', 'template', 'link', 'meta',
          'base', 'title',
        ]);

        if (TOXIC_TAGS.has(tag)) {
          // Remove the node and all its descendants
          node.removeChild(child);
        } else {
          // Unwrap: keep children, remove the wrapper element
          while (child.firstChild) {
            node.insertBefore(child.firstChild, child);
          }
          node.removeChild(child);
        }
        // Re-walk from this position since we inserted new nodes
        walkNode(node);
        return;
      }

      // --- Sanitize attributes ---
      var attrs = Array.prototype.slice.call(child.attributes);
      for (var j = 0; j < attrs.length; j++) {
        var attr = attrs[j];
        var aName = attr.name.toLowerCase();

        if (!isAllowedAttr(aName)) {
          child.removeAttribute(attr.name);
          continue;
        }

        // Validate URL attributes
        if (URL_ATTRS.has(aName)) {
          if (!isSafeUrl(attr.value)) {
            child.removeAttribute(attr.name);
            continue;
          }
        }

        // Sanitize style attribute: strip dangerous CSS patterns
        if (aName === 'style') {
          var styleVal = attr.value || '';
          if (/expression\s*\(/i.test(styleVal) ||
              /url\s*\(/i.test(styleVal) ||
              /-moz-binding/i.test(styleVal) ||
              /behavior\s*:/i.test(styleVal) ||
              /@import/gi.test(styleVal) ||
              /@charset/gi.test(styleVal) ||
              /var\s*\(/gi.test(styleVal) ||
              /-webkit-calc\s*\(/gi.test(styleVal) ||
              /content\s*:\s*attr\s*\(/gi.test(styleVal)) {
            child.removeAttribute(attr.name);
            continue;
          }
        }
      }

      // Enforce rel="noopener noreferrer" on links with target
      if (tag === 'a' && child.hasAttribute('target')) {
        child.setAttribute('rel', 'noopener noreferrer');
      }

      // Recurse into children
      walkNode(child);
    }
  }

  /* ── Public API ───────────────────────────────────────────────────── */

  /**
   * Sanitize an HTML string by parsing it with DOMParser and walking the
   * resulting tree.  Returns a safe HTML string.
   *
   * @param {string} dirty — untrusted HTML
   * @returns {string} — sanitized HTML safe for innerHTML assignment
   */
  function pocSanitize(dirty) {
    if (typeof dirty !== 'string' || dirty === '') return '';

    var doc = new DOMParser().parseFromString(dirty, 'text/html');
    walkNode(doc.body);
    return doc.body.innerHTML;
  }

  /**
   * Escape a plain-text string so it is safe to embed in HTML.
   *
   * Unlike the old `esc()`, this handles all five XML-mandated characters
   * plus backticks (which can be dangerous in certain attribute contexts
   * and template literals).
   *
   * Uses the browser's own textContent -> innerHTML conversion for the
   * core escaping, which is both faster and more correct than a regex.
   *
   * @param {*} str — value to escape (non-strings are converted)
   * @returns {string} — HTML-safe string
   */
  function pocEsc(str) {
    if (str == null) return '';
    var s = String(str);
    if (s === '') return '';

    // The browser handles &, <, >, " correctly via textContent.
    // We use a single element for the lifetime of the page.
    if (!pocEsc._el) {
      pocEsc._el = document.createElement('div');
    }
    pocEsc._el.textContent = s;
    var escaped = pocEsc._el.innerHTML;

    // The browser's innerHTML does NOT escape single quotes or backticks
    // inside textContent (only < > & " are escaped).  We add those
    // manually for safety in attribute contexts.
    escaped = escaped
      .replace(/'/g, '&#39;')
      .replace(/`/g, '&#96;');

    return escaped;
  }

  /* ── Expose globals ───────────────────────────────────────────────── */

  window.pocSanitize = pocSanitize;
  window.pocEsc = pocEsc;

})();

// Global State Shared across modules
window.AppState = {
  encodedJwt: "",
  headerObj: { alg: "HS256", typ: "JWT" },
  payloadObj: {},
  signature: "",
  secretKey: "your-256-bit-secret",
  isSignatureValid: false,
  autoSync: true,
  expandedAllClaims: {},
  collapsedAccordion: {},
  prettySearchTerm: "",
  rawSearchTerm: "",

  rawAllExpanded: true,
  prettyAllExpanded: true,

  foldedLinesHeader: {},
  foldedLinesPayload: {},
};

// Utilities Shared across modules
window.JWTUtils = {
  base64UrlEncode(str) {
    const base64 = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(str));
    return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  },

  base64UrlDecode(str) {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";
    try {
      return CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(base64));
    } catch (e) {
      return null;
    }
  },

  computeHmacSignature(headerB64, payloadB64, secret) {
    const dataToSign = `${headerB64}.${payloadB64}`;
    const hash = CryptoJS.HmacSHA256(dataToSign, secret);
    return CryptoJS.enc.Base64.stringify(hash)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  },

  verifySignature(headerB64, payloadB64, targetSignature, secret) {
    if (!targetSignature || !secret) return false;
    const expectedSig = this.computeHmacSignature(headerB64, payloadB64, secret);
    return expectedSig === targetSignature;
  },

  escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  },

  escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  },

  highlightText(text, filter) {
    const safeText = this.escapeHtml(text);
    if (!filter || !filter.trim()) return safeText;

    const regex = new RegExp(`(${this.escapeRegExp(filter.trim())})`, "gi");
    return safeText.replace(regex, `<span class="highlight-match">$1</span>`);
  },

  matchesFilter(key, val, filter) {
    if (key.toLowerCase().includes(filter)) return true;
    if (typeof val === "string" || typeof val === "number") {
      return String(val).toLowerCase().includes(filter);
    }
    if (Array.isArray(val)) {
      return val.some((item) => String(item).toLowerCase().includes(filter));
    }
    if (typeof val === "object" && val !== null) {
      return JSON.stringify(val).toLowerCase().includes(filter);
    }
    return false;
  },

  setupCopyButton(buttonEl, getTextFn) {
    if (!buttonEl) return;
    buttonEl.addEventListener("click", () => {
      const text = getTextFn();
      navigator.clipboard.writeText(text).then(() => {
        const originalText = buttonEl.textContent;
        buttonEl.textContent = "Copied!";
        setTimeout(() => {
          buttonEl.textContent = originalText;
        }, 1500);
      });
    });
  },

  findMatchingClosingLine(lines, startIdx) {
    let openCount = 0;
    for (let i = startIdx; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes("{") || line.includes("[")) openCount++;
      if (line.includes("}") || line.includes("]")) openCount--;
      if (openCount === 0) return i;
    }
    return -1;
  },

  setAllFoldedState(jsonObj, fold) {
    const map = {};
    if (!jsonObj) return map;

    const jsonStr = JSON.stringify(jsonObj, null, 2);
    const lines = jsonStr.split("\n");

    lines.forEach((line, i) => {
      if (i === 0) return;
      const lineTrim = line.trim();
      if (
        lineTrim.endsWith("{") ||
        lineTrim.endsWith("[") ||
        lineTrim.endsWith("{,") ||
        lineTrim.endsWith("[,")
      ) {
        map[i] = fold;
      }
    });

    return map;
  },

  renderFoldableCode(container, jsonObj, foldedStateMap, filterTerm) {
    container.innerHTML = "";
    if (!jsonObj || Object.keys(jsonObj).length === 0) return;

    const jsonStr = JSON.stringify(jsonObj, null, 2);
    const lines = jsonStr.split("\n");

    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      const lineTrim = line.trim();

      const canFold =
        i > 0 &&
        (lineTrim.endsWith("{") ||
          lineTrim.endsWith("[") ||
          lineTrim.endsWith("{,") ||
          lineTrim.endsWith("[,"));

      let isFolded = !!foldedStateMap[i];

      if (filterTerm && filterTerm.trim()) {
        let closingIdx = this.findMatchingClosingLine(lines, i);
        let blockText = lines.slice(i, closingIdx !== -1 ? closingIdx + 1 : i + 1).join("\n");
        if (blockText.toLowerCase().includes(filterTerm.toLowerCase().trim())) {
          isFolded = false;
        }
      }

      const lineEl = document.createElement("div");
      lineEl.className = "code-line";

      const foldBtn = document.createElement("span");
      foldBtn.className = "fold-btn";

      if (canFold) {
        foldBtn.textContent = isFolded ? "›" : "⌄";
        const lineIdx = i;
        foldBtn.addEventListener("click", () => {
          foldedStateMap[lineIdx] = !foldedStateMap[lineIdx];
          this.renderFoldableCode(container, jsonObj, foldedStateMap, filterTerm);
        });
      } else {
        foldBtn.textContent = " ";
      }

      lineEl.appendChild(foldBtn);

      const contentSpan = document.createElement("span");

      if (canFold && isFolded) {
        let matchingCloseIdx = this.findMatchingClosingLine(lines, i);
        let previewText = line;
        if (matchingCloseIdx !== -1) {
          previewText += " ... " + lines[matchingCloseIdx].trim();
        }

        contentSpan.innerHTML = this.highlightText(previewText, filterTerm);

        const lineIdx = i;
        contentSpan.addEventListener("click", () => {
          foldedStateMap[lineIdx] = false;
          this.renderFoldableCode(container, jsonObj, foldedStateMap, filterTerm);
        });

        lineEl.appendChild(contentSpan);
        container.appendChild(lineEl);

        if (matchingCloseIdx !== -1) {
          i = matchingCloseIdx;
        }
      } else {
        contentSpan.innerHTML = this.highlightText(line, filterTerm);
        lineEl.appendChild(contentSpan);
        container.appendChild(lineEl);
      }

      i++;
    }
  }
};

document.addEventListener("DOMContentLoaded", () => {
  const elements = {
    chkAutoSync: document.getElementById("chk-auto-sync"),
    jwtEncodedInput: document.getElementById("jwt-encoded-input"),
    secretKeyInput: document.getElementById("secret-key-input"),
    secretValidationBadge: document.getElementById("secret-validation-badge"),

    rawSearchInput: document.getElementById("raw-search-input"),
    rawHeaderContainer: document.getElementById("raw-header-container"),
    rawPayloadContainer: document.getElementById("raw-payload-container"),
    btnToggleAllRaw: document.getElementById("btn-toggle-all-raw"),

    prettySearchInput: document.getElementById("pretty-search-input"),
    prettyAccordion: document.getElementById("pretty-builder-accordion"),
    btnToggleAllPretty: document.getElementById("btn-toggle-all-pretty"),

    btnCopyEncodedTop: document.getElementById("btn-copy-encoded-top"),
    btnCopyEncodedBottom: document.getElementById("btn-copy-encoded-bottom"),
    btnCopyRawTop: document.getElementById("btn-copy-raw-top"),
    btnCopyRawBottom: document.getElementById("btn-copy-raw-bottom"),
  };

  function clearAllDecodedViews() {
    AppState.headerObj = {};
    AppState.payloadObj = {};
    AppState.signature = "";
    AppState.isSignatureValid = false;

    elements.rawHeaderContainer.innerHTML = "";
    elements.rawPayloadContainer.innerHTML = "";
    elements.prettyAccordion.innerHTML = "";
    updateValidationUI(false);
  }

  function parseEncodedJwt(token) {
    AppState.encodedJwt = token;

    if (!token.trim()) {
      elements.jwtEncodedInput.classList.remove("input-invalid");
      clearAllDecodedViews();
      return;
    }

    const parts = token.trim().split(".");
    let isValidStructure = false;

    if (parts.length === 1) {
      const payloadStr = JWTUtils.base64UrlDecode(parts[0]);
      if (payloadStr) {
        try {
          AppState.payloadObj = JSON.parse(payloadStr);
          AppState.headerObj = { alg: "HS256", typ: "JWT" };
          AppState.signature = "";
          isValidStructure = true;
          AppState.isSignatureValid = false;
        } catch (e) {}
      }
    } else if (parts.length >= 2) {
      const headerStr = JWTUtils.base64UrlDecode(parts[0]);
      const payloadStr = JWTUtils.base64UrlDecode(parts[1]);

      if (headerStr && payloadStr) {
        try {
          AppState.headerObj = JSON.parse(headerStr);
          AppState.payloadObj = JSON.parse(payloadStr);
          AppState.signature = parts[2] || "";
          isValidStructure = true;

          if (parts.length === 3 && parts[2]) {
            AppState.isSignatureValid = JWTUtils.verifySignature(
              parts[0],
              parts[1],
              AppState.signature,
              AppState.secretKey
            );
          } else {
            AppState.isSignatureValid = false;
          }
        } catch (e) {}
      }
    }

    if (!isValidStructure) {
      try {
        AppState.payloadObj = JSON.parse(token);
        AppState.headerObj = { alg: "HS256", typ: "JWT" };
        AppState.signature = "";
        isValidStructure = true;
        AppState.isSignatureValid = false;
      } catch (e) {}
    }

    if (isValidStructure) {
      elements.jwtEncodedInput.classList.remove("input-invalid");
      updateValidationUI(AppState.isSignatureValid);
      renderRawJsonView();
      renderPrettyBuilder();
    } else {
      elements.jwtEncodedInput.classList.add("input-invalid");
      clearAllDecodedViews();
    }
  }

  function buildAndSetEncodedJwt() {
    try {
      const headerB64 = JWTUtils.base64UrlEncode(JSON.stringify(AppState.headerObj));
      const payloadB64 = JWTUtils.base64UrlEncode(JSON.stringify(AppState.payloadObj));
      const newSignature = JWTUtils.computeHmacSignature(
        headerB64,
        payloadB64,
        AppState.secretKey
      );

      AppState.signature = newSignature;
      AppState.encodedJwt = `${headerB64}.${payloadB64}.${newSignature}`;
      AppState.isSignatureValid = true;

      elements.jwtEncodedInput.value = AppState.encodedJwt;
      elements.jwtEncodedInput.classList.remove("input-invalid");
      updateValidationUI(true);
    } catch (e) {}
  }

  function updateValidationUI(isValid) {
    AppState.isSignatureValid = isValid;
    if (isValid) {
      elements.secretValidationBadge.textContent = "VERIFIED";
      elements.secretValidationBadge.className = "badge badge-verified";
    } else {
      elements.secretValidationBadge.textContent = "INVALID";
      elements.secretValidationBadge.className = "badge badge-invalid";
    }
  }

  function renderRawJsonView() {
    JWTUtils.renderFoldableCode(
      elements.rawHeaderContainer,
      AppState.headerObj,
      AppState.foldedLinesHeader,
      AppState.rawSearchTerm
    );
    JWTUtils.renderFoldableCode(
      elements.rawPayloadContainer,
      AppState.payloadObj,
      AppState.foldedLinesPayload,
      AppState.rawSearchTerm
    );
  }

  function renderPrettyBuilder() {
    elements.prettyAccordion.innerHTML = "";

    const filter = AppState.prettySearchTerm.toLowerCase().trim();
    const keys = Object.keys(AppState.payloadObj);

    keys.forEach((key) => {
      const val = AppState.payloadObj[key];
      const match = filter ? JWTUtils.matchesFilter(key, val, filter) : true;
      if (filter && !match) return;

      renderClaimItem(
        elements.prettyAccordion,
        key,
        val,
        filter,
        true,
        match && !!filter,
        AppState.collapsedAccordion
      );
    });

    renderSignatureSection();
  }

  function renderClaimItem(
    container,
    key,
    val,
    filter,
    isEditable = true,
    forceOpen = false,
    collapsedStateMap = AppState.collapsedAccordion
  ) {
    const isArray = Array.isArray(val);
    const isObject = typeof val === "object" && val !== null && !isArray;

    let isCollapsed = collapsedStateMap[key];
    if (forceOpen) {
      isCollapsed = false;
    }

    const isAllExpanded = !!AppState.expandedAllClaims[key];

    const item = document.createElement("div");
    item.className = "claim-item";

    let typeBadge = "";
    if (isArray) typeBadge = `<span class="badge-tag">Array [${val.length}]</span>`;
    else if (isObject) typeBadge = `<span class="badge-tag">object</span>`;

    const allBtnHtml = isArray
      ? `<button class="btn-all-toggle ${isAllExpanded ? "active" : ""}" data-key="${JWTUtils.escapeHtml(key)}">All</button>`
      : "";

    const deleteBtnHtml = isEditable
      ? `<button class="btn-icon-action btn-delete-claim" data-key="${JWTUtils.escapeHtml(key)}" title="Delete claim">🗑</button>`
      : "";

    item.innerHTML = `
      <div class="claim-header" data-toggle="${JWTUtils.escapeHtml(key)}">
        <div class="claim-header-left">
          <span class="claim-title">${isCollapsed ? "›" : "⌄"} ${JWTUtils.highlightText(key, filter)}</span>
          ${typeBadge}
        </div>
        <div class="claim-header-right">
          ${allBtnHtml}
          ${deleteBtnHtml}
        </div>
      </div>
      <div class="claim-body" style="display: ${isCollapsed ? "none" : "block"}"></div>
    `;

    const headerEl = item.querySelector(".claim-header");
    headerEl.addEventListener("click", (e) => {
      if (e.target.closest(".btn-all-toggle") || e.target.closest(".btn-delete-claim")) return;
      collapsedStateMap[key] = !collapsedStateMap[key];
      renderPrettyBuilder();
    });

    if (isEditable) {
      const delBtn = item.querySelector(".btn-delete-claim");
      if (delBtn) {
        delBtn.addEventListener("click", () => {
          delete AppState.payloadObj[key];
          onPayloadModified();
        });
      }
    }

    const allBtn = item.querySelector(".btn-all-toggle");
    if (allBtn) {
      allBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        AppState.expandedAllClaims[key] = !AppState.expandedAllClaims[key];
        renderPrettyBuilder();
      });
    }

    const bodyEl = item.querySelector(".claim-body");
    if (!isCollapsed) {
      if (isArray) {
        renderArrayClaimBody(bodyEl, key, val, isAllExpanded, filter, isEditable);
      } else if (isObject) {
        if (isEditable) {
          bodyEl.innerHTML = `
            <div class="claim-edit-wrapper" style="flex-direction: column; align-items: stretch;">
              <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                <span class="pencil-icon" title="Editable JSON">✏️</span>
                <span style="font-size: 0.75rem; color: var(--text-dim);">Edit JSON object:</span>
              </div>
              <textarea class="object-json-textarea" data-key="${JWTUtils.escapeHtml(key)}">${JWTUtils.escapeHtml(
                JSON.stringify(val, null, 2)
              )}</textarea>
            </div>
          `;
          const textareaVal = bodyEl.querySelector(".object-json-textarea");
          
          textareaVal.addEventListener("input", (e) => {
            try {
              AppState.payloadObj[key] = JSON.parse(e.target.value);
              textareaVal.classList.remove("input-invalid");
              
              // Direct sync without full UI re-render to preserve typing focus
              renderRawJsonView();
              if (AppState.autoSync) {
                buildAndSetEncodedJwt();
              }
            } catch (err) {
              textareaVal.classList.add("input-invalid");
            }
          });
        } else {
          bodyEl.innerHTML = `<pre class="code-textarea" style="height: auto; font-size: 0.8rem;">${JWTUtils.highlightText(
            JSON.stringify(val, null, 2),
            filter
          )}</pre>`;
        }
      } else {
        if (isEditable) {
          bodyEl.innerHTML = `
            <div class="claim-edit-wrapper">
              <span class="pencil-icon" title="Editable">✏️</span>
              <input type="text" class="input-text claim-simple-value" data-key="${JWTUtils.escapeHtml(key)}" value="${JWTUtils.escapeHtml(String(val))}">
            </div>
          `;
          const inputVal = bodyEl.querySelector(".claim-simple-value");
          inputVal.addEventListener("input", (e) => {
            AppState.payloadObj[key] = e.target.value;
            onPayloadModified();
          });
        } else {
          bodyEl.innerHTML = `<div class="input-text claim-string-value" style="background: transparent; border: none;">${JWTUtils.highlightText(String(val), filter)}</div>`;
        }
      }
    }

    container.appendChild(item);
  }

  function renderArrayClaimBody(container, key, arrayVal, isAllExpanded, filter, isEditable) {
    let displayItems = arrayVal;
    const totalCount = arrayVal.length;
    const PREVIEW_LIMIT = 10;

    if (!isAllExpanded && totalCount > PREVIEW_LIMIT) {
      const visibleChips = displayItems.slice(0, PREVIEW_LIMIT);
      const remainingCount = totalCount - visibleChips.length;

      const previewContainer = document.createElement("div");
      previewContainer.className = "chips-preview-container";

      visibleChips.forEach((chipText, index) => {
        previewContainer.appendChild(createChipElement(key, chipText, index, isEditable, filter));
      });

      if (remainingCount > 0) {
        const moreLink = document.createElement("span");
        moreLink.className = "more-link";
        moreLink.textContent = `+${remainingCount} more`;
        moreLink.addEventListener("click", () => {
          AppState.expandedAllClaims[key] = true;
          renderPrettyBuilder();
        });
        previewContainer.appendChild(moreLink);
      }

      container.appendChild(previewContainer);
    } else {
      const box = document.createElement("div");
      box.className = "array-expanded-box";

      displayItems.forEach((chipText, index) => {
        box.appendChild(createChipElement(key, chipText, index, isEditable, filter));
      });

      container.appendChild(box);
    }

    if (isEditable) {
      const addBtn = document.createElement("button");
      addBtn.className = "btn-add-item";
      addBtn.textContent = "+ Add Item";
      addBtn.addEventListener("click", () => {
        const newItem = prompt(`Add new item to ${key}:`);
        if (newItem !== null && newItem.trim() !== "") {
          AppState.payloadObj[key].push(newItem.trim());
          onPayloadModified();
        }
      });
      container.appendChild(addBtn);
    }
  }

  function createChipElement(claimKey, text, index, isEditable, filter) {
    const chip = document.createElement("div");
    chip.className = "chip-item";

    const highlighted = JWTUtils.highlightText(String(text), filter);

    if (isEditable) {
      chip.innerHTML = `
        <span>${highlighted}</span>
        <span class="chip-remove" data-index="${index}">×</span>
      `;
      chip.querySelector(".chip-remove").addEventListener("click", () => {
        AppState.payloadObj[claimKey].splice(index, 1);
        onPayloadModified();
      });
    } else {
      chip.innerHTML = `<span>${highlighted}</span>`;
    }

    return chip;
  }

  function renderSignatureSection() {
    const item = document.createElement("div");
    item.className = "claim-item";
    const badgeClass = AppState.isSignatureValid ? "badge-verified" : "badge-invalid";
    const badgeText = AppState.isSignatureValid ? "VERIFIED" : "INVALID";

    item.innerHTML = `
      <div class="claim-header signature-block-header">
        <div class="claim-header-left">
          <span class="claim-title">☉ SIGNATURE</span>
          <span class="badge ${badgeClass}">${badgeText}</span>
        </div>
      </div>
    `;
    elements.prettyAccordion.appendChild(item);
  }

  function onPayloadModified() {
    renderRawJsonView();
    renderPrettyBuilder();
    if (AppState.autoSync) {
      buildAndSetEncodedJwt();
    }
  }

  elements.jwtEncodedInput.addEventListener("input", (e) => {
    parseEncodedJwt(e.target.value);
  });

  elements.secretKeyInput.addEventListener("input", (e) => {
    AppState.secretKey = e.target.value;
    const parts = AppState.encodedJwt.trim().split(".");

    if (parts.length === 3 && parts[0] && parts[1]) {
      AppState.isSignatureValid = JWTUtils.verifySignature(
        parts[0],
        parts[1],
        parts[2],
        AppState.secretKey
      );
      updateValidationUI(AppState.isSignatureValid);
    } else {
      updateValidationUI(false);
    }

    if (AppState.autoSync && parts.length >= 2) {
      buildAndSetEncodedJwt();
    }
  });

  elements.rawSearchInput.addEventListener("input", (e) => {
    AppState.rawSearchTerm = e.target.value;
    renderRawJsonView();
  });

  elements.prettySearchInput.addEventListener("input", (e) => {
    AppState.prettySearchTerm = e.target.value;
    renderPrettyBuilder();
  });

  elements.chkAutoSync.addEventListener("change", (e) => {
    AppState.autoSync = e.target.checked;
  });

  elements.btnToggleAllRaw.addEventListener("click", () => {
    AppState.rawAllExpanded = !AppState.rawAllExpanded;
    AppState.foldedLinesHeader = JWTUtils.setAllFoldedState(AppState.headerObj, !AppState.rawAllExpanded);
    AppState.foldedLinesPayload = JWTUtils.setAllFoldedState(AppState.payloadObj, !AppState.rawAllExpanded);
    renderRawJsonView();
  });

  elements.btnToggleAllPretty.addEventListener("click", () => {
    AppState.prettyAllExpanded = !AppState.prettyAllExpanded;
    Object.keys(AppState.payloadObj).forEach((k) => {
      AppState.collapsedAccordion[k] = !AppState.prettyAllExpanded;
    });
    renderPrettyBuilder();
  });

  JWTUtils.setupCopyButton(elements.btnCopyEncodedTop, () => AppState.encodedJwt);
  JWTUtils.setupCopyButton(elements.btnCopyEncodedBottom, () => AppState.encodedJwt);
  JWTUtils.setupCopyButton(elements.btnCopyRawTop, () => JSON.stringify(AppState.payloadObj, null, 2));
  JWTUtils.setupCopyButton(elements.btnCopyRawBottom, () => JSON.stringify(AppState.payloadObj, null, 2));

  parseEncodedJwt("");
});
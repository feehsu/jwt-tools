document.addEventListener("DOMContentLoaded", () => {
  const state = {
    encodedJwt: "",
    headerObj: { alg: "HS256", typ: "JWT" },
    payloadObj: {},
    signature: "",
    secretKey: "your-256-bit-secret",
    isSignatureValid: false,
    autoSync: true,
    expandedAllClaims: {},
    collapsedAccordion: {},
    searchTerm: "",
  };

  const elements = {
    chkAutoSync: document.getElementById("chk-auto-sync"),
    jwtEncodedInput: document.getElementById("jwt-encoded-input"),
    jwtHighlightOverlay: document.getElementById("jwt-highlight-overlay"),
    secretKeyInput: document.getElementById("secret-key-input"),
    secretValidationBadge: document.getElementById("secret-validation-badge"),

    tabBtnRaw: document.getElementById("tab-btn-raw"),
    tabBtnPretty: document.getElementById("tab-btn-pretty"),
    tabContentRaw: document.getElementById("tab-content-raw"),
    tabContentPretty: document.getElementById("tab-content-pretty"),

    rawJsonTextarea: document.getElementById("raw-json-textarea"),

    prettySearchInput: document.getElementById("pretty-search-input"),
    prettyAccordion: document.getElementById("pretty-builder-accordion"),

    btnCopyEncodedTop: document.getElementById("btn-copy-encoded-top"),
    btnCopyEncodedBottom: document.getElementById("btn-copy-encoded-bottom"),
    btnCopyDecodedTop: document.getElementById("btn-copy-decoded-top"),
    btnCopyDecodedBottom: document.getElementById("btn-copy-decoded-bottom"),
    btnCopyPrettyTop: document.querySelector(".btn-copy-json-pretty"),
    btnCopyPrettyBottom: document.getElementById("btn-copy-pretty-bottom"),

    comparatorJwtA: document.getElementById("comparator-jwt-a"),
    comparatorJwtB: document.getElementById("comparator-jwt-b"),
    comparatorResult: document.getElementById("comparator-result"),
  };

  function base64UrlEncode(str) {
    const base64 = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(str));
    return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }

  function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";
    try {
      return CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(base64));
    } catch (e) {
      return null;
    }
  }

  function computeHmacSignature(headerB64, payloadB64, secret) {
    const dataToSign = `${headerB64}.${payloadB64}`;
    const hash = CryptoJS.HmacSHA256(dataToSign, secret);
    return CryptoJS.enc.Base64.stringify(hash)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }

  function verifySignature(headerB64, payloadB64, targetSignature, secret) {
    if (!targetSignature || !secret) return false;
    const expectedSig = computeHmacSignature(headerB64, payloadB64, secret);
    return expectedSig === targetSignature;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderJwtHighlight(token) {
    if (!token || typeof token !== "string") {
      elements.jwtHighlightOverlay.innerHTML = "";
      return;
    }

    const parts = token.trim().split(".");

    if (parts.length === 3) {
      elements.jwtHighlightOverlay.innerHTML =
        `<span class="jwt-part-header">${escapeHtml(parts[0])}</span>` +
        `<span class="jwt-part-dot">.</span>` +
        `<span class="jwt-part-payload">${escapeHtml(parts[1])}</span>` +
        `<span class="jwt-part-dot">.</span>` +
        `<span class="jwt-part-signature">${escapeHtml(parts[2])}</span>`;
    } else if (parts.length === 1) {
      elements.jwtHighlightOverlay.innerHTML = `<span class="jwt-part-payload">${escapeHtml(parts[0])}</span>`;
    } else if (parts.length === 2) {
      elements.jwtHighlightOverlay.innerHTML =
        `<span class="jwt-part-header">${escapeHtml(parts[0])}</span>` +
        `<span class="jwt-part-dot">.</span>` +
        `<span class="jwt-part-payload">${escapeHtml(parts[1])}</span>`;
    } else {
      elements.jwtHighlightOverlay.textContent = token;
    }
  }

  function parseEncodedJwt(token) {
    state.encodedJwt = token;
    renderJwtHighlight(token);

    if (!token.trim()) {
      state.payloadObj = {};
      state.headerObj = { alg: "HS256", typ: "JWT" };
      state.signature = "";
      updateValidationUI(false);
      syncDecodedViews();
      return;
    }

    const parts = token.trim().split(".");

    if (parts.length === 1) {
      const payloadStr = base64UrlDecode(parts[0]);
      if (payloadStr) {
        try {
          state.payloadObj = JSON.parse(payloadStr);
          state.signature = "";
          updateValidationUI(false);
          syncDecodedViews();
          return;
        } catch (e) {}
      }
    }

    if (parts.length >= 2) {
      const headerStr = base64UrlDecode(parts[0]);
      const payloadStr = base64UrlDecode(parts[1]);

      if (headerStr && payloadStr) {
        try {
          state.headerObj = JSON.parse(headerStr);
          state.payloadObj = JSON.parse(payloadStr);
          state.signature = parts[2] || "";

          if (parts.length === 3) {
            state.isSignatureValid = verifySignature(
              parts[0],
              parts[1],
              state.signature,
              state.secretKey
            );
          } else {
            state.isSignatureValid = false;
          }

          updateValidationUI(state.isSignatureValid);
          syncDecodedViews();
          return;
        } catch (e) {}
      } else if (payloadStr) {
        try {
          state.payloadObj = JSON.parse(payloadStr);
          state.signature = "";
          updateValidationUI(false);
          syncDecodedViews();
          return;
        } catch (e) {}
      }
    }

    try {
      state.payloadObj = JSON.parse(token);
      state.signature = "";
      updateValidationUI(false);
      syncDecodedViews();
    } catch (e) {
      updateValidationUI(false);
    }
  }

  function buildAndSetEncodedJwt() {
    try {
      const headerB64 = base64UrlEncode(JSON.stringify(state.headerObj));
      const payloadB64 = base64UrlEncode(JSON.stringify(state.payloadObj));
      const newSignature = computeHmacSignature(
        headerB64,
        payloadB64,
        state.secretKey
      );

      state.signature = newSignature;
      state.encodedJwt = `${headerB64}.${payloadB64}.${newSignature}`;
      state.isSignatureValid = true;

      elements.jwtEncodedInput.value = state.encodedJwt;
      renderJwtHighlight(state.encodedJwt);
      updateValidationUI(true);
    } catch (e) {}
  }

  function updateValidationUI(isValid) {
    state.isSignatureValid = isValid;
    if (isValid) {
      elements.secretValidationBadge.textContent = "VERIFIED";
      elements.secretValidationBadge.className = "badge badge-verified";
    } else {
      elements.secretValidationBadge.textContent = "INVALID";
      elements.secretValidationBadge.className = "badge badge-invalid";
    }
    renderPrettyBuilder();
  }

  function syncDecodedViews() {
    elements.rawJsonTextarea.value = Object.keys(state.payloadObj).length
      ? JSON.stringify(state.payloadObj, null, 2)
      : "";
    renderPrettyBuilder();
  }

  function renderPrettyBuilder() {
    elements.prettyAccordion.innerHTML = "";

    renderHeaderSection();

    const filter = state.searchTerm.toLowerCase().trim();
    const keys = Object.keys(state.payloadObj);

    keys.forEach((key) => {
      const val = state.payloadObj[key];
      if (filter && !matchesFilter(key, val, filter)) {
        return;
      }
      renderClaimItem(key, val, filter);
    });

    renderSignatureSection();
  }

  function matchesFilter(key, val, filter) {
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
  }

  function renderHeaderSection() {
    const isCollapsed = state.collapsedAccordion["HEADER"];
    const algVal = state.headerObj.alg || "HS256";

    const item = document.createElement("div");
    item.className = "claim-item";
    item.innerHTML = `
      <div class="claim-header" data-toggle="HEADER">
        <div class="claim-header-left">
          <span class="claim-title">${isCollapsed ? "›" : "⌄"} HEADER</span>
          <span class="badge-tag">Alg: ${escapeHtml(algVal)}</span>
        </div>
      </div>
      ${
        !isCollapsed
          ? `<div class="claim-body"><pre class="code-textarea" style="height: auto; font-size: 0.8rem;">${escapeHtml(
              JSON.stringify(state.headerObj, null, 2)
            )}</pre></div>`
          : ""
      }
    `;

    item.querySelector(".claim-header").addEventListener("click", () => {
      state.collapsedAccordion["HEADER"] = !state.collapsedAccordion["HEADER"];
      renderPrettyBuilder();
    });

    elements.prettyAccordion.appendChild(item);
  }

  function renderClaimItem(key, val, filter) {
    const isArray = Array.isArray(val);
    const isObject = typeof val === "object" && val !== null && !isArray;
    const isCollapsed = state.collapsedAccordion[key];
    const isAllExpanded = !!state.expandedAllClaims[key];

    const item = document.createElement("div");
    item.className = "claim-item";

    let typeBadge = "";
    if (isArray) typeBadge = `<span class="badge-tag">Array [${val.length}]</span>`;
    else if (isObject) typeBadge = `<span class="badge-tag">object</span>`;

    const allBtnHtml = isArray
      ? `<button class="btn-all-toggle ${isAllExpanded ? "active" : ""}" data-key="${escapeHtml(key)}">All</button>`
      : "";

    item.innerHTML = `
      <div class="claim-header" data-toggle="${escapeHtml(key)}">
        <div class="claim-header-left">
          <span class="claim-title">${isCollapsed ? "›" : "⌄"} ${escapeHtml(key)}</span>
          ${typeBadge}
        </div>
        <div class="claim-header-right">
          ${allBtnHtml}
          <button class="btn-icon-action btn-delete-claim" data-key="${escapeHtml(key)}">×</button>
        </div>
      </div>
      <div class="claim-body" style="display: ${isCollapsed ? "none" : "block"}"></div>
    `;

    const headerEl = item.querySelector(".claim-header");
    headerEl.addEventListener("click", (e) => {
      if (e.target.closest(".btn-all-toggle") || e.target.closest(".btn-delete-claim")) return;
      state.collapsedAccordion[key] = !state.collapsedAccordion[key];
      renderPrettyBuilder();
    });

    const delBtn = item.querySelector(".btn-delete-claim");
    if (delBtn) {
      delBtn.addEventListener("click", () => {
        delete state.payloadObj[key];
        onPayloadModified();
      });
    }

    const allBtn = item.querySelector(".btn-all-toggle");
    if (allBtn) {
      allBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        state.expandedAllClaims[key] = !state.expandedAllClaims[key];
        renderPrettyBuilder();
      });
    }

    const bodyEl = item.querySelector(".claim-body");
    if (!isCollapsed) {
      if (isArray) {
        renderArrayClaimBody(bodyEl, key, val, isAllExpanded, filter);
      } else if (isObject) {
        bodyEl.innerHTML = `<pre class="code-textarea" style="height: auto; font-size: 0.8rem;">${escapeHtml(
          JSON.stringify(val, null, 2)
        )}</pre>`;
      } else {
        bodyEl.innerHTML = `
          <input type="text" class="input-text claim-simple-value" data-key="${escapeHtml(key)}" value="${escapeHtml(String(val))}">
        `;
        const inputVal = bodyEl.querySelector(".claim-simple-value");
        inputVal.addEventListener("change", (e) => {
          state.payloadObj[key] = e.target.value;
          onPayloadModified();
        });
      }
    }

    elements.prettyAccordion.appendChild(item);
  }

  function renderArrayClaimBody(container, key, arrayVal, isAllExpanded, filter) {
    let displayItems = arrayVal;
    if (filter) {
      displayItems = arrayVal.filter((item) =>
        String(item).toLowerCase().includes(filter)
      );
    }

    const totalCount = arrayVal.length;
    const PREVIEW_LIMIT = 3;

    if (!isAllExpanded && totalCount > PREVIEW_LIMIT) {
      const visibleChips = displayItems.slice(0, PREVIEW_LIMIT);
      const remainingCount = totalCount - visibleChips.length;

      const previewContainer = document.createElement("div");
      previewContainer.className = "chips-preview-container";

      visibleChips.forEach((chipText, index) => {
        previewContainer.appendChild(createChipElement(key, chipText, index));
      });

      if (remainingCount > 0) {
        const moreLink = document.createElement("span");
        moreLink.className = "more-link";
        moreLink.textContent = `+${remainingCount} more`;
        moreLink.addEventListener("click", () => {
          state.expandedAllClaims[key] = true;
          renderPrettyBuilder();
        });
        previewContainer.appendChild(moreLink);
      }

      container.appendChild(previewContainer);
    } else {
      const box = document.createElement("div");
      box.className = "array-expanded-box";

      displayItems.forEach((chipText, index) => {
        box.appendChild(createChipElement(key, chipText, index));
      });

      container.appendChild(box);

      const addBtn = document.createElement("button");
      addBtn.className = "btn-add-item";
      addBtn.textContent = "+ Add Item";
      addBtn.addEventListener("click", () => {
        const newItem = prompt(`Add new item to ${key}:`);
        if (newItem !== null && newItem.trim() !== "") {
          state.payloadObj[key].push(newItem.trim());
          onPayloadModified();
        }
      });
      container.appendChild(addBtn);
    }
  }

  function createChipElement(claimKey, text, index) {
    const chip = document.createElement("div");
    chip.className = "chip-item";
    chip.innerHTML = `
      <span>${escapeHtml(String(text))}</span>
      <span class="chip-remove" data-index="${index}">×</span>
    `;

    chip.querySelector(".chip-remove").addEventListener("click", () => {
      state.payloadObj[claimKey].splice(index, 1);
      onPayloadModified();
    });

    return chip;
  }

  function renderSignatureSection() {
    const item = document.createElement("div");
    item.className = "claim-item";
    const badgeClass = state.isSignatureValid ? "badge-verified" : "badge-invalid";
    const badgeText = state.isSignatureValid ? "VERIFIED" : "INVALID";

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
    syncDecodedViews();
    if (state.autoSync) {
      buildAndSetEncodedJwt();
    }
  }

  elements.jwtEncodedInput.addEventListener("input", (e) => {
    parseEncodedJwt(e.target.value);
  });

  elements.jwtEncodedInput.addEventListener("scroll", (e) => {
    elements.jwtHighlightOverlay.scrollTop = e.target.scrollTop;
    elements.jwtHighlightOverlay.scrollLeft = e.target.scrollLeft;
  });

  elements.secretKeyInput.addEventListener("input", (e) => {
    state.secretKey = e.target.value;
    if (state.autoSync) {
      buildAndSetEncodedJwt();
    } else {
      const parts = state.encodedJwt.trim().split(".");
      if (parts.length === 3) {
        state.isSignatureValid = verifySignature(
          parts[0],
          parts[1],
          parts[2],
          state.secretKey
        );
        updateValidationUI(state.isSignatureValid);
      }
    }
  });

  elements.rawJsonTextarea.addEventListener("input", (e) => {
    try {
      state.payloadObj = JSON.parse(e.target.value);
      renderPrettyBuilder();
      if (state.autoSync) {
        buildAndSetEncodedJwt();
      }
    } catch (err) {}
  });

  elements.prettySearchInput.addEventListener("input", (e) => {
    state.searchTerm = e.target.value;
    renderPrettyBuilder();
  });

  elements.tabBtnRaw.addEventListener("click", () => {
    elements.tabBtnRaw.classList.add("active");
    elements.tabBtnPretty.classList.remove("active");
    elements.tabContentRaw.classList.add("active");
    elements.tabContentPretty.classList.remove("active");
  });

  elements.tabBtnPretty.addEventListener("click", () => {
    elements.tabBtnPretty.classList.add("active");
    elements.tabBtnRaw.classList.remove("active");
    elements.tabContentPretty.classList.add("active");
    elements.tabContentRaw.classList.remove("active");
  });

  elements.chkAutoSync.addEventListener("change", (e) => {
    state.autoSync = e.target.checked;
  });

  function setupCopyButton(buttonEl, getTextFn) {
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
  }

  setupCopyButton(elements.btnCopyEncodedTop, () => state.encodedJwt);
  setupCopyButton(elements.btnCopyEncodedBottom, () => state.encodedJwt);
  setupCopyButton(elements.btnCopyDecodedTop, () => JSON.stringify(state.payloadObj, null, 2));
  setupCopyButton(elements.btnCopyDecodedBottom, () => JSON.stringify(state.payloadObj, null, 2));
  setupCopyButton(elements.btnCopyPrettyTop, () => JSON.stringify(state.payloadObj, null, 2));
  setupCopyButton(elements.btnCopyPrettyBottom, () => JSON.stringify(state.payloadObj, null, 2));

  function parsePayloadOnly(token) {
    if (!token) return null;
    const parts = token.trim().split(".");
    let payloadStr = "";

    if (parts.length === 3) payloadStr = base64UrlDecode(parts[1]);
    else if (parts.length === 2) payloadStr = base64UrlDecode(parts[1]);
    else if (parts.length === 1) payloadStr = base64UrlDecode(parts[0]);

    if (!payloadStr) return null;
    try {
      return JSON.parse(payloadStr);
    } catch (e) {
      return null;
    }
  }

  function compareJwts() {
    const rawA = elements.comparatorJwtA.value;
    const rawB = elements.comparatorJwtB.value;

    if (!rawA.trim() || !rawB.trim()) {
      elements.comparatorResult.style.display = "none";
      elements.comparatorResult.innerHTML = "";
      return;
    }

    const objA = parsePayloadOnly(rawA);
    const objB = parsePayloadOnly(rawB);

    elements.comparatorResult.style.display = "block";

    if (!objA || !objB) {
      elements.comparatorResult.innerHTML =
        '<span style="color: var(--accent-red)">Erro: Não foi possível decodificar o payload de um ou ambos os tokens para comparação.</span>';
      return;
    }

    const keysA = Object.keys(objA);
    const keysB = Object.keys(objB);
    const allKeys = Array.from(new Set([...keysA, ...keysB]));

    let diffHtml = "";
    let diffCount = 0;

    allKeys.forEach((key) => {
      const hasA = key in objA;
      const hasB = key in objB;

      if (hasA && !hasB) {
        diffCount++;
        diffHtml += `<div class="diff-line"><span class="diff-tag diff-removed">REMOVED</span> <strong>${escapeHtml(key)}</strong> (Presente apenas no JWT A): <code>${escapeHtml(JSON.stringify(objA[key]))}</code></div>`;
      } else if (!hasA && hasB) {
        diffCount++;
        diffHtml += `<div class="diff-line"><span class="diff-tag diff-added">ADDED</span> <strong>${escapeHtml(key)}</strong> (Presente apenas no JWT B): <code>${escapeHtml(JSON.stringify(objB[key]))}</code></div>`;
      } else {
        const strA = JSON.stringify(objA[key]);
        const strB = JSON.stringify(objB[key]);

        if (strA !== strB) {
          diffCount++;
          diffHtml += `<div class="diff-line"><span class="diff-tag diff-changed">CHANGED</span> <strong>${escapeHtml(key)}</strong>:<br>&nbsp;&nbsp;A: <code>${escapeHtml(strA)}</code><br>&nbsp;&nbsp;B: <code>${escapeHtml(strB)}</code></div>`;
        }
      }
    });

    if (diffCount === 0) {
      elements.comparatorResult.innerHTML =
        '<span style="color: var(--accent-green)">✔ Os payloads de ambos os JWTs são idênticos!</span>';
    } else {
      elements.comparatorResult.innerHTML =
        `<div style="margin-bottom: 10px; color: var(--text-dim); font-weight: bold;">Identificadas ${diffCount} diferença(s):</div>` + diffHtml;
    }
  }

  elements.comparatorJwtA.addEventListener("input", compareJwts);
  elements.comparatorJwtB.addEventListener("input", compareJwts);

  parseEncodedJwt("");
});
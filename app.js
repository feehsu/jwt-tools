/**
 * JWT Tools - Studio Pro
 * Lógica funcional unificada
 */

document.addEventListener("DOMContentLoaded", () => {
  // Estado interno da aplicação
  const state = {
    encodedJwt: "",
    headerObj: { alg: "HS256", typ: "JWT" },
    payloadObj: {},
    signature: "",
    secretKey: "your-256-bit-secret",
    isSignatureValid: false,
    autoSync: true,
    expandedAllClaims: {}, // Guarda quais claims estão expandidas via botão ALL
    collapsedAccordion: {}, // Guarda quais acordeões estão recolhidos
    searchTerm: "",
  };

  // Elementos do DOM
  const elements = {
    chkAutoSync: document.getElementById("chk-auto-sync"),
    jwtEncodedInput: document.getElementById("jwt-encoded-input"),
    jwtHighlightOverlay: document.getElementById("jwt-highlight-overlay"),
    secretKeyInput: document.getElementById("secret-key-input"),
    secretValidationBadge: document.getElementById("secret-validation-badge"),
    
    // Tabs
    tabBtnRaw: document.getElementById("tab-btn-raw"),
    tabBtnPretty: document.getElementById("tab-btn-pretty"),
    tabContentRaw: document.getElementById("tab-content-raw"),
    tabContentPretty: document.getElementById("tab-content-pretty"),

    // Raw JSON
    rawJsonTextarea: document.getElementById("raw-json-textarea"),

    // Pretty Builder
    prettySearchInput: document.getElementById("pretty-search-input"),
    prettyAccordion: document.getElementById("pretty-builder-accordion"),

    // Botões de Cópia
    btnCopyEncodedTop: document.getElementById("btn-copy-encoded-top"),
    btnCopyEncodedBottom: document.getElementById("btn-copy-encoded-bottom"),
    btnCopyDecodedTop: document.getElementById("btn-copy-decoded-top"),
    btnCopyDecodedBottom: document.getElementById("btn-copy-decoded-bottom"),
    btnCopyPrettyTop: document.querySelector(".btn-copy-json-pretty"),
    btnCopyPrettyBottom: document.getElementById("btn-copy-pretty-bottom"),

    // Comparator
    comparatorJwtA: document.getElementById("comparator-jwt-a"),
    comparatorJwtB: document.getElementById("comparator-jwt-b"),
    comparatorResult: document.getElementById("comparator-result"),
  };

  // Utilitários de Base64Url
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

  // Assinatura HMAC SHA256 e Validação
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

  // Colorizador de Encoded JWT (Ajuste 1)
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
    } else {
      elements.jwtHighlightOverlay.textContent = token;
    }
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // Parse do Encoded JWT -> Estado
  function parseEncodedJwt(token) {
    state.encodedJwt = token;
    renderJwtHighlight(token);

    const parts = token.trim().split(".");
    if (parts.length !== 3) {
      updateValidationUI(false);
      return;
    }

    const headerStr = base64UrlDecode(parts[0]);
    const payloadStr = base64UrlDecode(parts[1]);

    if (!headerStr || !payloadStr) {
      updateValidationUI(false);
      return;
    }

    try {
      state.headerObj = JSON.parse(headerStr);
      state.payloadObj = JSON.parse(payloadStr);
      state.signature = parts[2];

      state.isSignatureValid = verifySignature(
        parts[0],
        parts[1],
        state.signature,
        state.secretKey
      );

      updateValidationUI(state.isSignatureValid);
      syncDecodedViews();
    } catch (e) {
      updateValidationUI(false);
    }
  }

  // Recálculo e Codificação a partir do Estado Decodificado / Secret Key
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
    } catch (e) {
      console.error("Erro ao gerar JWT Encoded", e);
    }
  }

  // Atualização Visual do Badge de Validação do Secret Key
  function updateValidationUI(isValid) {
    state.isSignatureValid = isValid;
    if (isValid) {
      elements.secretValidationBadge.textContent = "VERIFIED";
      elements.secretValidationBadge.className = "badge badge-verified";
    } else {
      elements.secretValidationBadge.textContent = "INVALID";
      elements.secretValidationBadge.className = "badge badge-invalid";
    }
    renderPrettyBuilder(); // Atualiza a linha de assinatura no Pretty Builder
  }

  // Sincroniza abas Raw JSON e Pretty Builder
  function syncDecodedViews() {
    elements.rawJsonTextarea.value = JSON.stringify(state.payloadObj, null, 2);
    renderPrettyBuilder();
  }

  // Renderização do Pretty Builder
  function renderPrettyBuilder() {
    elements.prettyAccordion.innerHTML = "";

    // 1. Bloco HEADER
    renderHeaderSection();

    // 2. Claims do Payload
    const filter = state.searchTerm.toLowerCase().trim();
    const keys = Object.keys(state.payloadObj);

    keys.forEach((key) => {
      const val = state.payloadObj[key];
      if (filter && !matchesFilter(key, val, filter)) {
        return; // Filtra a claim
      }
      renderClaimItem(key, val, filter);
    });

    // 3. Bloco SIGNATURE
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

  // Renderiza a Seção do Header (alg/typ)
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

  // Renderiza cada Claim do Payload
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
      <div class="claim-body" style="display: ${isCollapsed ? "none" : "block"}">
        <!-- O corpo será injetado dinamicamente -->
      </div>
    `;

    // Eventos do Header
    const headerEl = item.querySelector(".claim-header");
    headerEl.addEventListener("click", (e) => {
      if (e.target.closest(".btn-all-toggle") || e.target.closest(".btn-delete-claim")) return;
      state.collapsedAccordion[key] = !state.collapsedAccordion[key];
      renderPrettyBuilder();
    });

    // Delete Claim
    const delBtn = item.querySelector(".btn-delete-claim");
    if (delBtn) {
      delBtn.addEventListener("click", () => {
        delete state.payloadObj[key];
        onPayloadModified();
      });
    }

    // Toggle ALL
    const allBtn = item.querySelector(".btn-all-toggle");
    if (allBtn) {
      allBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        state.expandedAllClaims[key] = !state.expandedAllClaims[key];
        renderPrettyBuilder();
      });
    }

    // Render do Corpo da Claim
    const bodyEl = item.querySelector(".claim-body");
    if (!isCollapsed) {
      if (isArray) {
        renderArrayClaimBody(bodyEl, key, val, isAllExpanded, filter);
      } else if (isObject) {
        bodyEl.innerHTML = `<pre class="code-textarea" style="height: auto; font-size: 0.8rem;">${escapeHtml(
          JSON.stringify(val, null, 2)
        )}</pre>`;
      } else {
        // Valor simples
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

  // Renderização do corpo do Array (Ajustes 4, 5 e 6)
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
      // Estado Resumido / Preview
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
      // Estado Expandido (Com caixa de scroll max-height)
      const box = document.createElement("div");
      box.className = "array-expanded-box";

      displayItems.forEach((chipText, index) => {
        box.appendChild(createChipElement(key, chipText, index));
      });

      container.appendChild(box);

      // Botão Add Item
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

  // Cria o elemento de cada Chip de Array
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

  // Renderiza a Seção de Assinatura no Pretty Builder
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

  // Callback ao modificar o Payload
  function onPayloadModified() {
    syncDecodedViews();
    if (state.autoSync) {
      buildAndSetEncodedJwt();
    }
  }

  // Listeners de Eventos

  // 1. Edição no Encoded JWT
  elements.jwtEncodedInput.addEventListener("input", (e) => {
    const val = e.target.value;
    parseEncodedJwt(val);
  });

  // Sincronização do Scroll da Overlay do Highlight
  elements.jwtEncodedInput.addEventListener("scroll", (e) => {
    elements.jwtHighlightOverlay.scrollTop = e.target.scrollTop;
    elements.jwtHighlightOverlay.scrollLeft = e.target.scrollLeft;
  });

  // 2. Edição no Secret Key
  elements.secretKeyInput.addEventListener("input", (e) => {
    state.secretKey = e.target.value;
    if (state.autoSync) {
      buildAndSetEncodedJwt();
    } else {
      // Apenas revalida a assinatura atual
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

  // 3. Edição na Aba Raw JSON
  elements.rawJsonTextarea.addEventListener("input", (e) => {
    try {
      state.payloadObj = JSON.parse(e.target.value);
      renderPrettyBuilder();
      if (state.autoSync) {
        buildAndSetEncodedJwt();
      }
    } catch (err) {
      // JSON inválido enquanto digita
    }
  });

  // 4. Busca / Filtro no Pretty Builder
  elements.prettySearchInput.addEventListener("input", (e) => {
    state.searchTerm = e.target.value;
    renderPrettyBuilder();
  });

  // 5. Alternância de Tabs
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

  // 6. Auto Sync Toggle
  elements.chkAutoSync.addEventListener("change", (e) => {
    state.autoSync = e.target.checked;
  });

  // 7. Botões de Cópia
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

  // Token de Inicialização de Exemplo
  const sampleToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicGVybWlzc2lvbnMiOlsiaW50ZWdyYXRpb24uZXhlY3V0aW9uLmdldCIsImludGVncmF0aW9uLmV4ZWN1dGlvbi5zdGFydCIsImludGVncmF0aW9uLndlYmhvb2siLCJpbnRlZ3JhdGlvbi5tYXJrZXRwbGFjZS5saXN0IiwiaW50ZWdyYXRpb24ubWFuYWdlbWVudC5lZGl0b3IiLCJ2Mi5iYWNrb2ZmaWNlIiwidjIubGl2ZSIsInYyLmJpbGxpbmciLCJ2Mi5hZG1pbiIsInBsYXRmb3JtLnByb2ZpbGUuZWRpdCIsInBsYXRmb3JtLnNlZ21lbnQudmlldyIsImZpbGVzLnVwbG9hZCIsImZpbGVzLmRvd25sb2FkLm93biIsImN1c3RvbWVyLnVzZXJzLnZpZXciLCJjdXN0b21lci51c2Vycy5jcmVhdGUiLCJjdX31Y3RvbWVyLnVzZXJzLmVkaXQiLCJjdXN0b21lci51c2Vycy5kZWxldGUiLCJjdXN0b21lci5vcmdhbml6YXRpb25zLnZpZXciLCJjdXN0b21lci5vcmdhbml6YXRpb25zLmVkaXQiLCJjdXN0b21lci5iaWxsaW5nLnZpZXciLCJjdXN0b21lci5iaWxsaW5nLmVkaXQiLCJjdXN0b21lci5pbnZvaWNlcy52aWV3IiwidXNlcnMucGF5Il0sInJvbGVzIjpbIm93bmVyIiwiYWRtaW4iXSwiY29tcGFueSI6eyJuYW1lIjoiUGxhdGFmb3JtYSIsInNsdWciOiJwbGF0YWZvcm1hLWNvcmUifX0." +
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  elements.jwtEncodedInput.value = sampleToken;
  parseEncodedJwt(sampleToken);
});

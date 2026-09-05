document.addEventListener("DOMContentLoaded", () => {
  const compState = {
    collapsedCompA: {},
    collapsedCompB: {},
    comparatorSearchTerm: "",
    activeComparatorTab: "pretty",

    compRawAAllExpanded: true,
    compRawBAllExpanded: true,
    compPrettyAAllExpanded: true,
    compPrettyBAllExpanded: true,

    compFoldedLinesA: {},
    compFoldedLinesB: {},
  };

  const elements = {
    comparatorJwtA: document.getElementById("comparator-jwt-a"),
    comparatorJwtB: document.getElementById("comparator-jwt-b"),
    comparatorSearchInput: document.getElementById("comparator-search-input"),
    compTabRaw: document.getElementById("comp-tab-raw"),
    compTabPretty: document.getElementById("comp-tab-pretty"),
    comparatorViewRaw: document.getElementById("comparator-view-raw"),
    comparatorViewPretty: document.getElementById("comparator-view-pretty"),

    compRawAContainer: document.getElementById("comp-raw-a-container"),
    compRawBContainer: document.getElementById("comp-raw-b-container"),
    compPrettyAAccordion: document.getElementById("comp-pretty-a-accordion"),
    compPrettyBAccordion: document.getElementById("comp-pretty-b-accordion"),

    btnToggleCompRawA: document.getElementById("btn-toggle-comp-raw-a"),
    btnToggleCompRawB: document.getElementById("btn-toggle-comp-raw-b"),
    btnToggleCompPrettyA: document.getElementById("btn-toggle-comp-pretty-a"),
    btnToggleCompPrettyB: document.getElementById("btn-toggle-comp-pretty-b"),

    btnCopyEncodedA: document.getElementById("btn-copy-encoded-a"),
    btnCopyJsonA: document.getElementById("btn-copy-json-a"),
    btnCopyEncodedB: document.getElementById("btn-copy-encoded-b"),
    btnCopyJsonB: document.getElementById("btn-copy-json-b"),
  };

  function tryParseJson(str) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }

  function decodeJwtPart(token) {
    if (!token) return null;
    const trimmed = token.trim();

    const jsonDirect = tryParseJson(trimmed);
    if (jsonDirect) return jsonDirect;

    const parts = trimmed.split(".");
    if (parts.length >= 2) {
      const decodedPayload = JWTUtils.base64UrlDecode(parts[1]);
      if (decodedPayload) {
        const jsonPayload = tryParseJson(decodedPayload);
        if (jsonPayload) return jsonPayload;
      }
    } else if (parts.length === 1) {
      const decodedSingle = JWTUtils.base64UrlDecode(parts[0]);
      if (decodedSingle) {
        const jsonSingle = tryParseJson(decodedSingle);
        if (jsonSingle) return jsonSingle;
      }
    }

    return null;
  }

  function validateComparatorInput(textareaEl, token) {
    if (!token.trim()) {
      textareaEl.classList.remove("input-invalid");
      return true;
    }
    const decoded = decodeJwtPart(token);
    if (decoded) {
      textareaEl.classList.remove("input-invalid");
      return true;
    } else {
      textareaEl.classList.add("input-invalid");
      return false;
    }
  }

  function renderComparatorClaimItem(container, key, val, filter, collapsedStateMap) {
    const isArray = Array.isArray(val);
    const isObject = typeof val === "object" && val !== null && !isArray;
    const isCollapsed = !!collapsedStateMap[key];

    const item = document.createElement("div");
    item.className = "claim-item";

    let typeBadge = "";
    if (isArray) typeBadge = `<span class="badge-tag">Array [${val.length}]</span>`;
    else if (isObject) typeBadge = `<span class="badge-tag">object</span>`;

    item.innerHTML = `
      <div class="claim-header">
        <div class="claim-header-left">
          <span class="claim-title">${isCollapsed ? "›" : "⌄"} ${JWTUtils.highlightText(key, filter)}</span>
          ${typeBadge}
        </div>
      </div>
      <div class="claim-body" style="display: ${isCollapsed ? "none" : "block"}"></div>
    `;

    item.querySelector(".claim-header").addEventListener("click", () => {
      collapsedStateMap[key] = !collapsedStateMap[key];
      updateComparatorViews();
    });

    const bodyEl = item.querySelector(".claim-body");
    if (!isCollapsed) {
      if (isArray) {
        const box = document.createElement("div");
        box.className = "array-expanded-box";
        val.forEach((chipText) => {
          const chip = document.createElement("div");
          chip.className = "chip-item";
          chip.innerHTML = `<span>${JWTUtils.highlightText(String(chipText), filter)}</span>`;
          box.appendChild(chip);
        });
        bodyEl.appendChild(box);
      } else if (isObject) {
        bodyEl.innerHTML = `<pre class="code-textarea" style="height: auto; font-size: 0.8rem;">${JWTUtils.highlightText(
          JSON.stringify(val, null, 2),
          filter
        )}</pre>`;
      } else {
        bodyEl.innerHTML = `<div class="claim-string-value">${JWTUtils.highlightText(String(val), filter)}</div>`;
      }
    }

    container.appendChild(item);
  }

  function updateComparatorViews() {
    const rawA = elements.comparatorJwtA.value;
    const rawB = elements.comparatorJwtB.value;

    validateComparatorInput(elements.comparatorJwtA, rawA);
    validateComparatorInput(elements.comparatorJwtB, rawB);

    const objA = decodeJwtPart(rawA) || {};
    const objB = decodeJwtPart(rawB) || {};

    const filter = compState.comparatorSearchTerm.toLowerCase().trim();

    if (compState.activeComparatorTab === "raw") {
      JWTUtils.renderFoldableCode(
        elements.compRawAContainer,
        objA,
        compState.compFoldedLinesA,
        filter
      );
      JWTUtils.renderFoldableCode(
        elements.compRawBContainer,
        objB,
        compState.compFoldedLinesB,
        filter
      );
    } else {
      elements.compPrettyAAccordion.innerHTML = "";
      elements.compPrettyBAccordion.innerHTML = "";

      const keysA = Object.keys(objA);
      const keysB = Object.keys(objB);

      keysA.forEach((key) => {
        const val = objA[key];
        const match = filter ? JWTUtils.matchesFilter(key, val, filter) : true;
        if (!filter || match) {
          renderComparatorClaimItem(
            elements.compPrettyAAccordion,
            key,
            val,
            filter,
            compState.collapsedCompA
          );
        }
      });

      keysB.forEach((key) => {
        const val = objB[key];
        const match = filter ? JWTUtils.matchesFilter(key, val, filter) : true;
        if (!filter || match) {
          renderComparatorClaimItem(
            elements.compPrettyBAccordion,
            key,
            val,
            filter,
            compState.collapsedCompB
          );
        }
      });

      highlightDiffInPretty(elements.compPrettyAAccordion, elements.compPrettyBAccordion, objA, objB);
    }
  }

  function highlightDiffInPretty(accA, accB, objA, objB) {
    const itemsA = accA.querySelectorAll(".claim-item");
    const itemsB = accB.querySelectorAll(".claim-item");

    itemsA.forEach((item) => {
      const titleEl = item.querySelector(".claim-title");
      if (titleEl) {
        const key = titleEl.textContent.replace(/^[›⌄]\s*/, "").trim();
        if (!(key in objB)) {
          item.classList.add("diff-highlight-removed");
        } else if (JSON.stringify(objA[key]) !== JSON.stringify(objB[key])) {
          item.classList.add("diff-highlight-changed");
        }
      }
    });

    itemsB.forEach((item) => {
      const titleEl = item.querySelector(".claim-title");
      if (titleEl) {
        const key = titleEl.textContent.replace(/^[›⌄]\s*/, "").trim();
        if (!(key in objA)) {
          item.classList.add("diff-highlight-added");
        } else if (JSON.stringify(objA[key]) !== JSON.stringify(objB[key])) {
          item.classList.add("diff-highlight-changed");
        }
      }
    });
  }

  elements.comparatorJwtA.addEventListener("input", updateComparatorViews);
  elements.comparatorJwtB.addEventListener("input", updateComparatorViews);
  elements.comparatorSearchInput.addEventListener("input", (e) => {
    compState.comparatorSearchTerm = e.target.value;
    updateComparatorViews();
  });

  elements.compTabRaw.addEventListener("click", () => {
    compState.activeComparatorTab = "raw";
    elements.compTabRaw.classList.add("active");
    elements.compTabPretty.classList.remove("active");
    elements.comparatorViewRaw.classList.add("active");
    elements.comparatorViewPretty.classList.remove("active");
    updateComparatorViews();
  });

  elements.compTabPretty.addEventListener("click", () => {
    compState.activeComparatorTab = "pretty";
    elements.compTabPretty.classList.add("active");
    elements.compTabRaw.classList.remove("active");
    elements.comparatorViewPretty.classList.add("active");
    elements.comparatorViewRaw.classList.remove("active");
    updateComparatorViews();
  });

  elements.btnToggleCompRawA.addEventListener("click", () => {
    compState.compRawAAllExpanded = !compState.compRawAAllExpanded;
    const objA = decodeJwtPart(elements.comparatorJwtA.value) || {};
    compState.compFoldedLinesA = JWTUtils.setAllFoldedState(objA, !compState.compRawAAllExpanded);
    updateComparatorViews();
  });

  elements.btnToggleCompRawB.addEventListener("click", () => {
    compState.compRawBAllExpanded = !compState.compRawBAllExpanded;
    const objB = decodeJwtPart(elements.comparatorJwtB.value) || {};
    compState.compFoldedLinesB = JWTUtils.setAllFoldedState(objB, !compState.compRawBAllExpanded);
    updateComparatorViews();
  });

  elements.btnToggleCompPrettyA.addEventListener("click", () => {
    compState.compPrettyAAllExpanded = !compState.compPrettyAAllExpanded;
    const objA = decodeJwtPart(elements.comparatorJwtA.value) || {};
    Object.keys(objA).forEach((k) => {
      compState.collapsedCompA[k] = !compState.compPrettyAAllExpanded;
    });
    updateComparatorViews();
  });

  elements.btnToggleCompPrettyB.addEventListener("click", () => {
    compState.compPrettyBAllExpanded = !compState.compPrettyBAllExpanded;
    const objB = decodeJwtPart(elements.comparatorJwtB.value) || {};
    Object.keys(objB).forEach((k) => {
      compState.collapsedCompB[k] = !compState.compPrettyBAllExpanded;
    });
    updateComparatorViews();
  });

  JWTUtils.setupCopyButton(elements.btnCopyEncodedA, () => elements.comparatorJwtA.value);
  JWTUtils.setupCopyButton(elements.btnCopyJsonA, () => {
    const parsed = decodeJwtPart(elements.comparatorJwtA.value);
    return parsed ? JSON.stringify(parsed, null, 2) : "";
  });

  JWTUtils.setupCopyButton(elements.btnCopyEncodedB, () => elements.comparatorJwtB.value);
  JWTUtils.setupCopyButton(elements.btnCopyJsonB, () => {
    const parsed = decodeJwtPart(elements.comparatorJwtB.value);
    return parsed ? JSON.stringify(parsed, null, 2) : "";
  });
});
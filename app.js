const encodedInput = document.getElementById('encoded');
const decodedEditor = document.getElementById('decoded-editor');
const prettyBuilder = document.getElementById('pretty-builder');
const errorEncoded = document.getElementById('error-encoded');
const errorDecoded = document.getElementById('error-decoded');
const autoSyncCheck = document.getElementById('auto-sync');
const secretKeyInput = document.getElementById('secret-key');
const btnEncodeManual = document.getElementById('btn-encode-manual');
const btnDecodeManual = document.getElementById('btn-decode-manual');

let currentJsonObject = {};
let headerJsonObject = { alg: "HS256", typ: "JWT" };
let currentSignature = "";
let isUpdating = false;

const arrayViewModes = {};
const compArrayViewModes = { 1: {}, 2: {} };

document.getElementById('tab-btn-raw').addEventListener('click', () => switchTab('raw'));
document.getElementById('tab-btn-pretty').addEventListener('click', () => switchTab('pretty'));

autoSyncCheck.addEventListener('change', () => {
    const auto = autoSyncCheck.checked;
    btnEncodeManual.style.display = auto ? 'none' : 'inline-block';
    btnDecodeManual.style.display = auto ? 'none' : 'inline-block';
});

function switchTab(tabName) {
    document.querySelectorAll('.panel-right .tabs .tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.panel-right .tab-content').forEach(c => c.classList.remove('active'));

    if (tabName === 'raw') {
        document.getElementById('tab-btn-raw').classList.add('active');
        document.getElementById('tab-raw').classList.add('active');
    } else {
        document.getElementById('tab-btn-pretty').classList.add('active');
        document.getElementById('tab-pretty').classList.add('active');
        renderPrettyUI();
    }
}

function copyText(text, buttonEl) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        const originalText = buttonEl.textContent;
        buttonEl.textContent = 'Copied!';
        buttonEl.style.borderColor = 'var(--accent-green)';
        buttonEl.style.color = 'var(--accent-green)';
        
        setTimeout(() => {
            buttonEl.textContent = originalText;
            buttonEl.style.borderColor = '';
            buttonEl.style.color = '';
        }, 1500);
    });
}

function getDecodedText() {
    return decodedEditor.innerText || decodedEditor.textContent;
}

document.getElementById('btn-copy-encoded-top').addEventListener('click', function() { copyText(encodedInput.value, this); });
document.getElementById('btn-copy-encoded-bottom').addEventListener('click', function() { copyText(encodedInput.value, this); });

document.getElementById('btn-copy-decoded-top').addEventListener('click', function() { copyText(getDecodedText(), this); });
document.getElementById('btn-copy-decoded-bottom').addEventListener('click', function() { copyText(getDecodedText(), this); });
document.getElementById('btn-copy-pretty-bottom').addEventListener('click', function() { copyText(getDecodedText(), this); });

btnDecodeManual.addEventListener('click', () => handleDecode(true));
btnEncodeManual.addEventListener('click', () => handleEncode(true));

function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    const jsonString = decodeURIComponent(atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
    return JSON.parse(jsonString);
}

function base64UrlEncode(obj) {
    const jsonString = typeof obj === 'string' ? obj : JSON.stringify(obj);
    const base64 = btoa(encodeURIComponent(jsonString).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function signHmacSHA256(unsignedToken, secret) {
    const signature = CryptoJS.HmacSHA256(unsignedToken, secret);
    return CryptoJS.enc.Base64.stringify(signature)
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateToken() {
    const encodedHeader = base64UrlEncode(headerJsonObject);
    const encodedPayload = base64UrlEncode(currentJsonObject);
    const unsignedToken = `${encodedHeader}.${encodedPayload}`;
    
    const secret = secretKeyInput.value.trim();
    if (secret) {
        currentSignature = signHmacSHA256(unsignedToken, secret);
    }
    return `${unsignedToken}.${currentSignature}`;
}

function syntaxHighlightJson(jsonObj) {
    const json = JSON.stringify(jsonObj, null, 2);
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'json-number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'json-key';
            } else {
                cls = 'json-string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'json-boolean';
        } else if (/null/.test(match)) {
            cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

function updateRawEditor(jsonObj) {
    decodedEditor.innerHTML = syntaxHighlightJson(jsonObj);
}

function handleDecode(force = false) {
    if (isUpdating || (!autoSyncCheck.checked && !force)) return;
    isUpdating = true;
    errorEncoded.textContent = '';

    try {
        const rawText = encodedInput.value.trim();
        if (!rawText) {
            currentJsonObject = {};
            decodedEditor.innerHTML = '';
            prettyBuilder.innerHTML = '';
        } else {
            const parts = rawText.split('.');
            if (parts.length >= 2) {
                headerJsonObject = base64UrlDecode(parts[0]);
                currentJsonObject = base64UrlDecode(parts[1]);
                currentSignature = parts[2] || "";
            } else {
                currentJsonObject = base64UrlDecode(parts[0]);
            }
            updateRawEditor(currentJsonObject);
            if (document.getElementById('tab-pretty').classList.contains('active')) {
                renderPrettyUI();
            }
        }
    } catch (e) {
        errorEncoded.textContent = 'Invalid Token or Base64 structure.';
    }
    isUpdating = false;
}

function handleEncode(force = false) {
    if (isUpdating || (!autoSyncCheck.checked && !force)) return;
    isUpdating = true;
    errorDecoded.textContent = '';

    try {
        currentJsonObject = JSON.parse(getDecodedText());
        encodedInput.value = generateToken();
        if (document.getElementById('tab-pretty').classList.contains('active')) {
            renderPrettyUI();
        }
    } catch (e) {
        errorDecoded.textContent = 'Invalid JSON in Raw editor.';
    }
    isUpdating = false;
}

encodedInput.addEventListener('input', () => handleDecode());
decodedEditor.addEventListener('input', () => handleEncode());
secretKeyInput.addEventListener('input', () => { if (autoSyncCheck.checked) handleEncode(true); });

function epochToDatetimeLocal(epoch) {
    const date = new Date(epoch * 1000);
    const pad = num => String(num).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function datetimeLocalToEpoch(datetimeStr) {
    return Math.floor(new Date(datetimeStr).getTime() / 1000);
}

function adjustTextareaHeight(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = Math.max(textarea.scrollHeight, 40) + 'px';
}

function updateEyeIcon(accordionEl, eyeIconEl) {
    eyeIconEl.textContent = accordionEl.classList.contains('open') ? '👁️' : '🙈';
}

function renderPrettyUI() {
    prettyBuilder.innerHTML = '';

    const headerBlock = document.createElement('div');
    headerBlock.className = 'accordion-item open';
    
    const headerHeader = document.createElement('div');
    headerHeader.className = 'accordion-header';
    headerHeader.innerHTML = `
        <div class="accordion-header-left">
            <span class="icon-eye">👁️</span>
            <span>HEADER</span>
            <span class="badge badge-green">Alg: ${headerJsonObject.alg || 'HS256'}</span>
        </div>
    `;
    const headerEye = headerHeader.querySelector('.icon-eye');
    headerHeader.onclick = () => {
        headerBlock.classList.toggle('open');
        updateEyeIcon(headerBlock, headerEye);
    };

    headerBlock.appendChild(headerHeader);
    headerBlock.innerHTML += `
        <div class="accordion-body">
            <div class="highlight-editor" style="min-height: auto;">${syntaxHighlightJson(headerJsonObject)}</div>
        </div>
    `;
    prettyBuilder.appendChild(headerBlock);

    const payloadBlock = document.createElement('div');
    payloadBlock.className = 'accordion-item open';
    
    let expBadgeHtml = '';
    if (currentJsonObject.exp) {
        const now = Math.floor(Date.now() / 1000);
        const isExpired = currentJsonObject.exp < now;
        expBadgeHtml = `<span class="badge ${isExpired ? 'badge-amber' : 'badge-green'}">${isExpired ? 'Expired' : 'Valid'}</span>`;
    }

    const payloadHeader = document.createElement('div');
    payloadHeader.className = 'accordion-header';
    payloadHeader.innerHTML = `
        <div class="accordion-header-left">
            <span class="icon-eye">👁️</span>
            <span>PAYLOAD</span>
            ${expBadgeHtml}
        </div>
    `;
    const payloadEye = payloadHeader.querySelector('.icon-eye');
    payloadHeader.onclick = () => {
        payloadBlock.classList.toggle('open');
        updateEyeIcon(payloadBlock, payloadEye);
    };

    const payloadBody = document.createElement('div');
    payloadBody.className = 'accordion-body';

    if (!currentJsonObject || Object.keys(currentJsonObject).length === 0) {
        payloadBody.innerHTML = '<span style="color:var(--text-dim)">Empty Payload.</span>';
    } else {
        Object.keys(currentJsonObject).forEach(key => {
            const val = currentJsonObject[key];
            const isArr = Array.isArray(val);

            if (isArr && !arrayViewModes[key]) {
                arrayViewModes[key] = 'chips';
            }

            const itemEl = document.createElement('div');
            itemEl.className = 'accordion-item open';
            itemEl.style.marginBottom = '8px';

            const header = document.createElement('div');
            header.className = 'accordion-header';
            
            const headerLeft = document.createElement('div');
            headerLeft.className = 'accordion-header-left';
            headerLeft.innerHTML = `
                <span class="icon-eye">👁️</span>
                <span>${key}</span> 
                <small style="color:var(--text-dim)">${isArr ? 'Array [' + val.length + ']' : typeof val}</small>
            `;
            const itemEye = headerLeft.querySelector('.icon-eye');

            const headerRight = document.createElement('div');
            headerRight.className = 'accordion-header-right';

            if (isArr) {
                const toggleBtn = document.createElement('button');
                toggleBtn.className = 'btn-toggle-view';
                const currentMode = arrayViewModes[key];
                
                toggleBtn.innerHTML = `🔄 ${currentMode === 'chips' ? 'Chips' : 'List'}`;
                toggleBtn.title = 'Switch View: Chips / List';

                toggleBtn.onclick = (e) => {
                    e.stopPropagation();
                    arrayViewModes[key] = arrayViewModes[key] === 'chips' ? 'list' : 'chips';
                    renderPrettyUI();
                };
                headerRight.appendChild(toggleBtn);
            }

            const deleteKeyBtn = document.createElement('button');
            deleteKeyBtn.className = 'btn-del';
            deleteKeyBtn.textContent = 'X';
            deleteKeyBtn.onclick = (e) => {
                e.stopPropagation();
                delete currentJsonObject[key];
                delete arrayViewModes[key];
                syncFromPretty(true);
            };
            headerRight.appendChild(deleteKeyBtn);

            header.appendChild(headerLeft);
            header.appendChild(headerRight);
            
            header.onclick = (e) => {
                if (!e.target.closest('button') && !e.target.closest('input')) {
                    itemEl.classList.toggle('open');
                    updateEyeIcon(itemEl, itemEye);
                }
            };

            const body = document.createElement('div');
            body.className = 'accordion-body';

            const timeClaims = ['iat', 'exp', 'nbf'];
            if (timeClaims.includes(key.toLowerCase()) && typeof val === 'number') {
                const dateObj = new Date(val * 1000);
                
                const fieldGroup = document.createElement('div');
                fieldGroup.className = 'field-group';
                
                const numInput = document.createElement('input');
                numInput.type = 'text';
                numInput.value = val;
                numInput.oninput = () => {
                    const parsed = Number(numInput.value);
                    if (!isNaN(parsed)) {
                        currentJsonObject[key] = parsed;
                        syncFromPretty(false);
                    }
                };

                const timeRow = document.createElement('div');
                timeRow.className = 'time-row';

                const pickerInput = document.createElement('input');
                pickerInput.type = 'datetime-local';
                pickerInput.value = epochToDatetimeLocal(val);
                pickerInput.onchange = () => {
                    const newEpoch = datetimeLocalToEpoch(pickerInput.value);
                    if (!isNaN(newEpoch)) {
                        currentJsonObject[key] = newEpoch;
                        numInput.value = newEpoch;
                        syncFromPretty(false);
                    }
                };

                const dateLabel = document.createElement('span');
                dateLabel.textContent = `${dateObj.toLocaleDateString()} ${dateObj.toLocaleTimeString()}`;

                timeRow.appendChild(pickerInput);
                timeRow.appendChild(dateLabel);

                fieldGroup.appendChild(numInput);
                fieldGroup.appendChild(timeRow);
                body.appendChild(fieldGroup);

            } else if (isArr) {
                const activeMode = arrayViewModes[key];

                if (activeMode === 'chips') {
                    const chipGrid = document.createElement('div');
                    chipGrid.className = 'array-grid-container';
                    val.forEach((itemVal, idx) => {
                        const chip = document.createElement('div');
                        chip.className = 'array-chip';

                        const inp = document.createElement('input');
                        inp.type = 'text';
                        inp.value = typeof itemVal === 'object' ? JSON.stringify(itemVal) : itemVal;
                        inp.style.width = Math.max(inp.value.length * 8, 40) + 'px';
                        inp.oninput = () => {
                            currentJsonObject[key][idx] = inp.value;
                            inp.style.width = Math.max(inp.value.length * 8, 40) + 'px';
                            syncFromPretty(false);
                        };

                        const btnDel = document.createElement('button');
                        btnDel.className = 'btn-del';
                        btnDel.style.padding = '0 4px';
                        btnDel.textContent = '×';
                        btnDel.onclick = () => {
                            currentJsonObject[key].splice(idx, 1);
                            syncFromPretty(true);
                        };

                        chip.appendChild(inp);
                        chip.appendChild(btnDel);
                        chipGrid.appendChild(chip);
                    });
                    body.appendChild(chipGrid);
                } else {
                    val.forEach((itemVal, idx) => {
                        const row = document.createElement('div');
                        row.className = 'list-item';

                        const txt = document.createElement('input');
                        txt.type = 'text';
                        txt.value = typeof itemVal === 'object' ? JSON.stringify(itemVal) : itemVal;
                        txt.oninput = () => {
                            currentJsonObject[key][idx] = txt.value;
                            syncFromPretty(false);
                        };

                        const btnDel = document.createElement('button');
                        btnDel.className = 'btn-del';
                        btnDel.textContent = 'X';
                        btnDel.onclick = () => {
                            currentJsonObject[key].splice(idx, 1);
                            syncFromPretty(true);
                        };

                        row.appendChild(txt);
                        row.appendChild(btnDel);
                        body.appendChild(row);
                    });
                }

                const btnAdd = document.createElement('button');
                btnAdd.className = 'btn-add';
                btnAdd.style.marginTop = '8px';
                btnAdd.textContent = '+ Add Item';
                btnAdd.onclick = () => {
                    currentJsonObject[key].push("new_item");
                    syncFromPretty(true);
                };
                body.appendChild(btnAdd);

            } else if (typeof val === 'object' && val !== null) {
                const subArea = document.createElement('textarea');
                subArea.className = 'auto-adjust-obj';
                subArea.value = JSON.stringify(val, null, 2);
                
                subArea.oninput = () => {
                    adjustTextareaHeight(subArea);
                    try {
                        currentJsonObject[key] = JSON.parse(subArea.value);
                        syncFromPretty(false);
                    } catch(e){}
                };
                
                body.appendChild(subArea);
                setTimeout(() => adjustTextareaHeight(subArea), 0);

            } else {
                const group = document.createElement('div');
                group.className = 'field-group';
                const inp = document.createElement('input');
                inp.type = 'text';
                inp.value = val;
                inp.oninput = () => {
                    let parsedVal = inp.value;
                    if (!isNaN(inp.value) && inp.value.trim() !== '') parsedVal = Number(inp.value);
                    currentJsonObject[key] = parsedVal;
                    syncFromPretty(false);
                };
                group.appendChild(inp);
                body.appendChild(group);
            }

            itemEl.appendChild(header);
            itemEl.appendChild(body);
            payloadBody.appendChild(itemEl);
        });
    }

    payloadBlock.appendChild(payloadHeader);
    payloadBlock.appendChild(payloadBody);
    prettyBuilder.appendChild(payloadBlock);

    const sigBlock = document.createElement('div');
    sigBlock.className = 'accordion-item open';
    
    const sigHeader = document.createElement('div');
    sigHeader.className = 'accordion-header';
    sigHeader.innerHTML = `
        <div class="accordion-header-left">
            <span class="icon-eye">👁️</span>
            <span>SIGNATURE</span>
            <span class="badge badge-green">VERIFIED</span>
        </div>
    `;
    const sigEye = sigHeader.querySelector('.icon-eye');
    sigHeader.onclick = () => {
        sigBlock.classList.toggle('open');
        updateEyeIcon(sigBlock, sigEye);
    };

    sigBlock.appendChild(sigHeader);
    sigBlock.innerHTML += `
        <div class="accordion-body">
            <div style="font-family: monospace; font-size: 11px; color: var(--text-dim); word-break: break-all;">
                ${currentSignature || 'No signature'}
            </div>
        </div>
    `;
    prettyBuilder.appendChild(sigBlock);
}

function syncFromPretty(reRenderUI = false) {
    updateRawEditor(currentJsonObject);
    
    if (isUpdating || !autoSyncCheck.checked) return;
    isUpdating = true;
    encodedInput.value = generateToken();
    isUpdating = false;

    if (reRenderUI) {
        renderPrettyUI();
    }
}

const compJwt1 = document.getElementById('comp-jwt-1');
const compJwt2 = document.getElementById('comp-jwt-2');
const comp1RawText = document.getElementById('comp-1-raw-text');
const comp2RawText = document.getElementById('comp-2-raw-text');
const comp1Pretty = document.getElementById('comp-1-pretty');
const comp2Pretty = document.getElementById('comp-2-pretty');

document.getElementById('comp1-tab-raw').addEventListener('click', () => switchCompTab(1, 'raw'));
document.getElementById('comp1-tab-pretty').addEventListener('click', () => switchCompTab(1, 'pretty'));
document.getElementById('comp2-tab-raw').addEventListener('click', () => switchCompTab(2, 'raw'));
document.getElementById('comp2-tab-pretty').addEventListener('click', () => switchCompTab(2, 'pretty'));

function switchCompTab(panelNum, tabName) {
    const card = document.querySelectorAll('.comparator-card')[panelNum - 1];
    card.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    
    const rawContent = document.getElementById(`comp-${panelNum}-raw`);
    const prettyContent = document.getElementById(`comp-${panelNum}-pretty`);

    rawContent.classList.remove('active');
    prettyContent.classList.remove('active');

    if (tabName === 'raw') {
        card.querySelectorAll('.tab-btn')[0].classList.add('active');
        rawContent.classList.add('active');
    } else {
        card.querySelectorAll('.tab-btn')[1].classList.add('active');
        prettyContent.classList.add('active');
    }
}

function parseTokenPayload(tokenStr) {
    if (!tokenStr.trim()) return null;
    try {
        const parts = tokenStr.trim().split('.');
        if (parts.length >= 2) return base64UrlDecode(parts[1]);
        return base64UrlDecode(parts[0]);
    } catch (e) {
        return null;
    }
}

function runComparison() {
    const compObj1 = parseTokenPayload(compJwt1.value);
    const compObj2 = parseTokenPayload(compJwt2.value);

    comp1RawText.innerHTML = compObj1 ? syntaxHighlightJson(compObj1) : '';
    comp2RawText.innerHTML = compObj2 ? syntaxHighlightJson(compObj2) : '';

    renderCompPretty(1, compObj1, compObj2);
    renderCompPretty(2, compObj2, compObj1);
}

function renderCompPretty(panelNum, primaryObj, targetObj) {
    const container = panelNum === 1 ? comp1Pretty : comp2Pretty;
    container.innerHTML = '';

    if (!primaryObj) {
        container.innerHTML = '<span style="color:var(--text-dim)">No valid payload.</span>';
        return;
    }

    Object.keys(primaryObj).forEach(key => {
        const val = primaryObj[key];
        const targetVal = targetObj ? targetObj[key] : undefined;
        const isDifferent = JSON.stringify(val) !== JSON.stringify(targetVal);
        const isArr = Array.isArray(val);

        if (isArr && !compArrayViewModes[panelNum][key]) {
            compArrayViewModes[panelNum][key] = 'chips';
        }

        const itemEl = document.createElement('div');
        itemEl.className = 'accordion-item open';

        const header = document.createElement('div');
        header.className = 'accordion-header';
        if (isDifferent) header.classList.add('diff-highlight');
        
        const headerLeft = document.createElement('div');
        headerLeft.className = 'accordion-header-left';
        headerLeft.innerHTML = `
            <span class="icon-eye">👁️</span>
            <span>${key}</span> 
            <small style="color:${isDifferent ? '#FFF2A8' : 'var(--text-dim)'}">${isArr ? 'Array [' + val.length + ']' : typeof val}</small>
        `;
        const itemEye = headerLeft.querySelector('.icon-eye');

        const headerRight = document.createElement('div');
        headerRight.className = 'accordion-header-right';

        if (isArr) {
            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'btn-toggle-view';
            const currentMode = compArrayViewModes[panelNum][key];
            
            toggleBtn.innerHTML = `🔄 ${currentMode === 'chips' ? 'Chips' : 'List'}`;
            toggleBtn.title = 'Switch View: Chips / List';

            toggleBtn.onclick = (e) => {
                e.stopPropagation();
                compArrayViewModes[panelNum][key] = compArrayViewModes[panelNum][key] === 'chips' ? 'list' : 'chips';
                runComparison();
            };
            headerRight.appendChild(toggleBtn);
        }

        header.appendChild(headerLeft);
        header.appendChild(headerRight);

        const body = document.createElement('div');
        body.className = 'accordion-body';

        if (isArr) {
            const activeMode = compArrayViewModes[panelNum][key];

            if (activeMode === 'chips') {
                const chipGrid = document.createElement('div');
                chipGrid.className = 'array-grid-container';
                
                val.forEach((itemVal, idx) => {
                    const targetArrVal = Array.isArray(targetVal) ? targetVal[idx] : undefined;
                    const isItemDiff = JSON.stringify(itemVal) !== JSON.stringify(targetArrVal);

                    const chip = document.createElement('div');
                    chip.className = 'array-chip';

                    const inp = document.createElement('input');
                    inp.type = 'text';
                    inp.readOnly = true;
                    inp.value = typeof itemVal === 'object' ? JSON.stringify(itemVal) : itemVal;
                    inp.style.width = Math.max(inp.value.length * 8, 40) + 'px';
                    if (isItemDiff) inp.classList.add('diff-highlight-text');

                    chip.appendChild(inp);
                    chipGrid.appendChild(chip);
                });
                body.appendChild(chipGrid);
            } else {
                val.forEach((itemVal, idx) => {
                    const targetArrVal = Array.isArray(targetVal) ? targetVal[idx] : undefined;
                    const isItemDiff = JSON.stringify(itemVal) !== JSON.stringify(targetArrVal);

                    const row = document.createElement('div');
                    row.className = 'list-item';

                    const txt = document.createElement('input');
                    txt.type = 'text';
                    txt.readOnly = true;
                    txt.value = typeof itemVal === 'object' ? JSON.stringify(itemVal) : itemVal;
                    if (isItemDiff) txt.classList.add('diff-highlight-text');

                    row.appendChild(txt);
                    body.appendChild(row);
                });
            }
        } else if (typeof val === 'object' && val !== null) {
            const subArea = document.createElement('textarea');
            subArea.className = 'auto-adjust-obj';
            subArea.readOnly = true;
            subArea.value = JSON.stringify(val, null, 2);
            if (isDifferent) subArea.classList.add('diff-highlight-text');
            body.appendChild(subArea);
            setTimeout(() => adjustTextareaHeight(subArea), 0);
        } else {
            const group = document.createElement('div');
            group.className = 'field-group';
            const inp = document.createElement('input');
            inp.type = 'text';
            inp.readOnly = true;
            inp.value = val;
            if (isDifferent) inp.classList.add('diff-highlight-text');
            group.appendChild(inp);
            body.appendChild(group);
        }

        header.onclick = (e) => {
            if (!e.target.closest('button')) {
                itemEl.classList.toggle('open');
                updateEyeIcon(itemEl, itemEye);
            }
        };
        itemEl.appendChild(header);
        itemEl.appendChild(body);
        container.appendChild(itemEl);
    });
}

compJwt1.addEventListener('input', runComparison);
compJwt2.addEventListener('input', runComparison);

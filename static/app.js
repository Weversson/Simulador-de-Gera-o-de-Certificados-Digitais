const $ = s => document.querySelector(s);
const api = (u, o={}) => fetch(u, {headers:{"Content-Type":"application/json"}, ...o}).then(async r=>{
  if(!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
});

const toast = (msg, err=false) => {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err?" err":"");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(()=>t.hidden=true, 3200);
};

const fmt = iso => new Date(iso).toLocaleString("pt-BR",{dateStyle:"short",timeStyle:"short"});

async function carregarStats(){
  const s = await api("/api/stats");
  $("#stat-total").textContent = s.total;
  let p2048 = s.por_tamanho["2048"] || 0;
  let p4096 = (s.por_tamanho["4096"]||0)+(s.por_tamanho["3072"]||0)+(s.por_tamanho["8192"]||0);
  animarNumero($("#stat-total"), s.total);
  animarNumero($("#stat-2048"), p2048);
  animarNumero($("#stat-4096"), p4096);
}

function animarNumero(el, alvo){
  const atual = parseInt(el.dataset.v || "0");
  const passos = 20;
  let i = 0;
  const tick = () => {
    i++;
    const v = Math.round(atual + (alvo-atual)*(i/passos));
    el.textContent = v;
    if(i<passos) requestAnimationFrame(tick);
    else el.dataset.v = alvo;
  };
  tick();
}

async function carregarLista(){
  const itens = await api("/api/certificados");
  const el = $("#list");
  if(!itens.length){
    el.innerHTML = '<div class="empty">⊘ nenhum certificado emitido · use o painel ao lado</div>';
    return;
  }
  el.innerHTML = itens.map(c=>`
    <div class="item">
      <div class="idx">#${String(c.id).padStart(4,"0")}</div>
      <div class="meta">
        <span class="cn">${escapar(c.common_name)} · ${escapar(c.organization)}</span>
        <span class="sub">${c.country}/${escapar(c.state)}/${escapar(c.locality)} · ${c.key_size}b · ${c.signature_algorithm} · ${fmt(c.created_at)}</span>
      </div>
      <div class="acts">
        <button class="icon-btn" title="ver detalhes" onclick="detalhar(${c.id})">⌕</button>
        <button class="icon-btn" title="baixar certificado público" onclick="baixar(${c.id},'certificate')">⇣C</button>
        <button class="icon-btn danger" title="revogar" onclick="deletar(${c.id})">×</button>
      </div>
    </div>`).join("");
}

function escapar(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}

async function detalhar(id){
  const c = await api(`/api/certificados/${id}`);
  $("#modal-body").innerHTML = `
    <h3>Certificado #${String(c.id).padStart(4,"0")}</h3>
    <div class="modal-sub">SERIAL · ${c.serial_number}</div>
    <dl class="kv">
      <dt>Nome comum</dt><dd>${escapar(c.common_name)}</dd>
      <dt>Organização</dt><dd>${escapar(c.organization)}</dd>
      <dt>País</dt><dd>${c.country}</dd>
      <dt>Estado</dt><dd>${escapar(c.state)}</dd>
      <dt>Cidade</dt><dd>${escapar(c.locality)}</dd>
      <dt>Chave RSA</dt><dd>${c.key_size} bits</dd>
      <dt>Assinatura</dt><dd>${c.signature_algorithm}</dd>
      <dt>Emissor</dt><dd>autoassinado</dd>
      <dt>Válido de</dt><dd>${fmt(c.not_before)}</dd>
      <dt>Válido até</dt><dd>${fmt(c.not_after)}</dd>
    </dl>
    <pre class="pem">${c.certificate_pem}</pre>
  `;
  $("#modal").hidden = false;
}

function baixar(id, tipo){
  window.location = `/api/certificados/${id}/download/${tipo}`;
  toast(`baixando ${tipo==="certificate"?"certificado":"chave privada"}…`);
}

async function deletar(id){
  if(!confirm(`Revogar certificado #${id}? Esta ação é irreversível.`)) return;
  try{
    await api(`/api/certificados/${id}`,{method:"DELETE"});
    toast("certificado revogado");
    await Promise.all([carregarLista(), carregarStats()]);
  }catch(e){toast(e.message, true)}
}

$("#modal-close").onclick = ()=>$("#modal").hidden = true;
$("#modal").onclick = e => {if(e.target.id==="modal") $("#modal").hidden = true};

$("#refresh-btn").onclick = async ()=>{
  await Promise.all([carregarLista(), carregarStats()]);
  toast("vault atualizado");
};

$("#geo-btn").onclick = async ()=>{
  $("#geo-hint").textContent = "⟳ consultando GeoIP…";
  try{
    const g = await api("/api/geoip");
    if(g.erro){$("#geo-hint").textContent = "✗ não foi possível detectar"; return}
    $("#state").value = g.estado || $("#state").value;
    $("#locality").value = g.cidade || $("#locality").value;
    $("#geo-hint").textContent = `⟟ ${g.ip} · ${g.cidade}, ${g.estado} (${g.pais})`;
  }catch(e){$("#geo-hint").textContent = "✗ "+e.message}
};

$("#form").onsubmit = async e => {
  e.preventDefault();
  const btn = e.target.querySelector("button[type=submit]");
  btn.disabled = true;
  btn.querySelector("span").textContent = "FORJANDO…";
  const fd = new FormData(e.target);
  const body = Object.fromEntries(fd.entries());
  body.key_size = parseInt(body.key_size);
  try{
    const r = await api("/api/certificados",{method:"POST",body:JSON.stringify(body)});
    mostrarChavePrivadaUnica(r);
    await Promise.all([carregarLista(), carregarStats()]);
  }catch(err){toast(err.message, true)}
  finally{
    btn.disabled = false;
    btn.querySelector("span").textContent = "GERAR CERTIFICADO";
  }
};

function mostrarChavePrivadaUnica(r){
  const pem = r.private_key_pem;
  const nome = `private_key_${r.id}.pem`;
  $("#modal-body").innerHTML = `
    <h3>⚠ Chave Privada · Emissão Única</h3>
    <div class="modal-sub">CERTIFICADO #${String(r.id).padStart(4,"0")} · ${r.serial_number.slice(0,24)}…</div>
    <div class="warning-box">
      <strong>ESTA É A ÚNICA VEZ QUE VOCÊ VERÁ ESTA CHAVE PRIVADA.</strong><br>
      Em conformidade com a ICP-Brasil, a Autoridade Certificadora <b>não armazena</b> cópia da chave privada.
      Baixe e guarde em local seguro agora — se perder, o certificado será inutilizável.
    </div>
    <div class="actions" style="margin-bottom:16px">
      <button class="btn-primary" id="dl-priv">⇣ BAIXAR CHAVE PRIVADA (.pem)</button>
      <button class="btn-ghost" id="copy-priv">⎘ copiar</button>
    </div>
    <pre class="pem">${escapar(pem)}</pre>
  `;
  $("#modal").hidden = false;
  $("#dl-priv").onclick = () => {
    const blob = new Blob([pem], {type:"application/x-pem-file"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = nome;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("chave privada salva · não será mais exibida");
  };
  $("#copy-priv").onclick = async () => {
    await navigator.clipboard.writeText(pem);
    toast("chave copiada para a área de transferência");
  };
}

// ---------- auth ----------
let modoAuth = "login";

document.querySelectorAll(".tab").forEach(t => t.onclick = () => {
  modoAuth = t.dataset.mode;
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
  $("#auth-submit span").textContent = modoAuth === "login" ? "ENTRAR" : "REGISTRAR";
  $("#auth-hint").textContent = "";
});

$("#auth-form").onsubmit = async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {username: fd.get("username"), password: fd.get("password")};
  const btn = $("#auth-submit");
  btn.disabled = true;
  $("#auth-hint").textContent = "⟳ autenticando…";
  try {
    await api(`/api/auth/${modoAuth === "login" ? "login" : "register"}`, {
      method: "POST", body: JSON.stringify(body),
    });
    await mostrarApp();
    toast(modoAuth === "login" ? "sessão iniciada" : "conta criada");
  } catch (err) {
    $("#auth-hint").textContent = "✗ " + err.message;
  } finally {
    btn.disabled = false;
  }
};

$("#logout-btn").onclick = async () => {
  await api("/api/auth/logout", {method: "POST"});
  mostrarAuth();
  toast("sessão encerrada");
};

function mostrarAuth() {
  $("#main").hidden = true;
  $("#user-badge").hidden = true;
  $("#auth-screen").hidden = false;
  $("#auth-form").reset();
  $("#auth-hint").textContent = "";
}

async function mostrarApp() {
  const me = await api("/api/auth/me");
  if (!me.autenticado) { mostrarAuth(); return; }
  $("#user-name").textContent = "◈ " + me.username;
  $("#user-badge").hidden = false;
  $("#auth-screen").hidden = true;
  $("#main").hidden = false;
  await Promise.all([carregarLista(), carregarStats()]);
}

// init
(async()=>{
  try {
    const me = await api("/api/auth/me");
    if (me.autenticado) await mostrarApp();
    else mostrarAuth();
  } catch { mostrarAuth(); }
})();

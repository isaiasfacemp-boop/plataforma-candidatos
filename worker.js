// Worker da Plataforma de Candidatos
// Precisa do binding D1 com o nome de variável "DB".

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400'
};
const PARTE = 900000;                 // tamanho de cada pedaço de arquivo no banco
const MAX_ARQUIVO = 20 * 1024 * 1024; // 20 MB (em texto base64)
const SESSAO_DIAS = 30;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS }
  });
}
function erro(msg, status = 400) { return json({ erro: msg }, status); }

function novoId(prefixo) {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return prefixo + Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}
async function sha256(txt) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(txt));
  return Array.from(new Uint8Array(buf), x => x.toString(16).padStart(2, '0')).join('');
}
function refsDe(texto) {
  const set = new Set();
  if (!texto) return set;
  const re = /arquivo:([A-Za-z0-9_-]+)/g;
  let m;
  while ((m = re.exec(texto))) set.add(m[1]);
  return set;
}
const idValido = id => typeof id === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(id);

// ---------- arquivos ----------
async function salvarArquivo(env, id, dataUrl) {
  if (!idValido(id) || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:')) return;
  if (dataUrl.length > MAX_ARQUIVO) throw new Error('Arquivo muito grande (máx. ~15 MB).');
  const stmts = [env.DB.prepare('DELETE FROM arquivos_partes WHERE arquivo_id = ?').bind(id)];
  for (let i = 0, p = 0; i < dataUrl.length; i += PARTE, p++) {
    stmts.push(env.DB.prepare('INSERT INTO arquivos_partes (arquivo_id, parte, conteudo) VALUES (?, ?, ?)')
      .bind(id, p, dataUrl.slice(i, i + PARTE)));
  }
  await env.DB.batch(stmts);
}
async function lerArquivo(env, id) {
  const { results } = await env.DB.prepare(
    'SELECT conteudo FROM arquivos_partes WHERE arquivo_id = ? ORDER BY parte').bind(id).all();
  if (!results.length) return null;
  return results.map(r => r.conteudo).join('');
}
async function apagarArquivos(env, ids) {
  for (const id of ids) {
    await env.DB.prepare('DELETE FROM arquivos_partes WHERE arquivo_id = ?').bind(id).run();
  }
}

// ---------- sessão ----------
async function usuarioDaSessao(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;
  const s = await env.DB.prepare('SELECT usuario_id, criado_em FROM sessoes WHERE token = ?').bind(token).first();
  if (!s) return null;
  if (Date.now() - new Date(s.criado_em).getTime() > SESSAO_DIAS * 86400000) {
    await env.DB.prepare('DELETE FROM sessoes WHERE token = ?').bind(token).run();
    return null;
  }
  const u = await env.DB.prepare("SELECT dados FROM registros WHERE tipo = 'usuario' AND id = ?").bind(s.usuario_id).first();
  if (!u) return null;
  const dados = JSON.parse(u.dados);
  return { token, id: dados.id, nome: dados.nome, usuario: dados.usuario, perfil: dados.perfil, precisaTrocarSenha: !!dados.precisaTrocarSenha };
}
function semSenha(dadosTxt) {
  const o = JSON.parse(dadosTxt);
  delete o.senha;
  return o;
}

// ---------- rotas ----------
async function login(env, body) {
  const usuario = String(body.usuario || '').trim().toLowerCase();
  const senha = String(body.senha || '');
  let { results } = await env.DB.prepare("SELECT id, dados FROM registros WHERE tipo = 'usuario'").all();

  // banco novo: cria o admin padrão (admin / admin)
  if (!results.length) {
    const admin = { id: novoId('u_'), nome: 'Administrador', usuario: 'admin', senha: 'sha256:' + await sha256('admin'), perfil: 'Administrador' };
    await env.DB.prepare("INSERT INTO registros (tipo, id, dados, atualizado_em) VALUES ('usuario', ?, ?, ?)")
      .bind(admin.id, JSON.stringify(admin), new Date().toISOString()).run();
    results = [{ id: admin.id, dados: JSON.stringify(admin) }];
  }

  const hash = 'sha256:' + await sha256(senha);
  let achado = null;
  for (const r of results) {
    const u = JSON.parse(r.dados);
    if (String(u.usuario || '').toLowerCase() === usuario && (u.senha === hash || u.senha === senha)) { achado = u; break; }
  }
  if (!achado) return erro('Usuário ou senha inválidos.', 401);

  const token = novoId('t_') + novoId('');
  await env.DB.prepare('INSERT INTO sessoes (token, usuario_id, criado_em) VALUES (?, ?, ?)')
    .bind(token, achado.id, new Date().toISOString()).run();
  return json({ token, usuario: { id: achado.id, nome: achado.nome, usuario: achado.usuario, perfil: achado.perfil, precisaTrocarSenha: !!achado.precisaTrocarSenha } });
}

async function dados(env) {
  const { results } = await env.DB.prepare('SELECT tipo, id, dados FROM registros').all();
  const out = { candidatos: [], usuarios: [], mensagens: [], config: null };
  for (const r of results) {
    if (r.tipo === 'candidato') out.candidatos.push(JSON.parse(r.dados));
    else if (r.tipo === 'usuario') out.usuarios.push(semSenha(r.dados));
    else if (r.tipo === 'mensagem') out.mensagens.push(JSON.parse(r.dados));
    else if (r.tipo === 'config' && r.id === 'geral') out.config = JSON.parse(r.dados);
  }
  out.candidatos.sort((a, b) => String(b.criadoEm || '').localeCompare(String(a.criadoEm || '')));
  out.mensagens.sort((a, b) => String(b.criadoEm || '').localeCompare(String(a.criadoEm || '')));
  return json(out);
}

const PERMISSOES = {
  candidato: ['Administrador', 'Membro'],
  mensagem: ['Administrador', 'Membro'],
  usuario: ['Administrador'],
  config: ['Administrador']
};
const pode = (perfil, tipo) => (PERMISSOES[tipo] || []).includes(perfil);

async function verificarSenha(env, user, body) {
  const senha = String((body && body.senha) || '');
  const r = await env.DB.prepare("SELECT dados FROM registros WHERE tipo = 'usuario' AND id = ?").bind(user.id).first();
  if (!r) return erro('Usuário não encontrado.', 404);
  const u = JSON.parse(r.dados);
  const hash = 'sha256:' + await sha256(senha);
  if (u.senha !== hash && u.senha !== senha) return erro('Senha incorreta.', 401);
  return json({ ok: true });
}

async function trocarSenha(env, user, body) {
  const atual = String((body && body.senhaAtual) || '');
  const nova = String((body && body.novaSenha) || '');
  if (nova.length < 4) return erro('A nova senha precisa ter pelo menos 4 caracteres.', 400);
  const r = await env.DB.prepare("SELECT dados FROM registros WHERE tipo = 'usuario' AND id = ?").bind(user.id).first();
  if (!r) return erro('Usuário não encontrado.', 404);
  const u = JSON.parse(r.dados);
  const hashAtual = 'sha256:' + await sha256(atual);
  if (u.senha !== hashAtual && u.senha !== atual) return erro('Senha atual incorreta.', 401);
  u.senha = 'sha256:' + await sha256(nova);
  u.precisaTrocarSenha = false;
  await env.DB.prepare("UPDATE registros SET dados = ?, atualizado_em = ? WHERE tipo = 'usuario' AND id = ?")
    .bind(JSON.stringify(u), new Date().toISOString(), user.id).run();
  return json({ ok: true });
}

async function sync(env, user, body) {
  const agora = new Date().toISOString();
  const arquivos = Array.isArray(body.arquivos) ? body.arquivos : [];
  const salvar = Array.isArray(body.salvar) ? body.salvar : [];
  const excluir = Array.isArray(body.excluir) ? body.excluir : [];
  const podeArquivo = user.perfil === 'Administrador' || user.perfil === 'Membro';

  if (podeArquivo) {
    for (const a of arquivos) await salvarArquivo(env, a.id, a.dataUrl);
  }

  const orfaos = new Set();
  const usados = new Set();

  for (const item of salvar) {
    if (!pode(user.perfil, item.tipo) || !idValido(item.id) || typeof item.dados !== 'string') continue;
    let dadosTxt = item.dados;
    const antigo = await env.DB.prepare('SELECT dados FROM registros WHERE tipo = ? AND id = ?').bind(item.tipo, item.id).first();

    if (item.tipo === 'usuario') {
      const novo = JSON.parse(dadosTxt);
      if (novo.senha && !String(novo.senha).startsWith('sha256:')) novo.senha = 'sha256:' + await sha256(String(novo.senha));
      if (!novo.senha && antigo) novo.senha = JSON.parse(antigo.dados).senha; // mantém a senha atual
      dadosTxt = JSON.stringify(novo);
    }

    await env.DB.prepare(
      'INSERT INTO registros (tipo, id, dados, atualizado_em) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(tipo, id) DO UPDATE SET dados = excluded.dados, atualizado_em = excluded.atualizado_em'
    ).bind(item.tipo, item.id, dadosTxt, agora).run();

    refsDe(dadosTxt).forEach(r => usados.add(r));
    if (antigo) refsDe(antigo.dados).forEach(r => orfaos.add(r));
  }

  for (const item of excluir) {
    if (!pode(user.perfil, item.tipo) || !idValido(item.id)) continue;
    if (item.tipo === 'usuario' && item.id === user.id) continue; // não apaga a si mesmo
    const antigo = await env.DB.prepare('SELECT dados FROM registros WHERE tipo = ? AND id = ?').bind(item.tipo, item.id).first();
    if (!antigo) continue;
    await env.DB.prepare('DELETE FROM registros WHERE tipo = ? AND id = ?').bind(item.tipo, item.id).run();
    if (item.tipo === 'usuario') await env.DB.prepare('DELETE FROM sessoes WHERE usuario_id = ?').bind(item.id).run();
    refsDe(antigo.dados).forEach(r => orfaos.add(r));
  }

  usados.forEach(r => orfaos.delete(r));
  if (orfaos.size) await apagarArquivos(env, orfaos);
  return json({ ok: true });
}

// ---------- links de cadastro de uso único ----------
async function statusConvite(env, token) {
  if (!idValido(token)) return { valido: false, motivo: 'inexistente' };
  const cv = await env.DB.prepare('SELECT usado_em, cancelado FROM convites WHERE token = ?').bind(token).first();
  if (!cv) return { valido: false, motivo: 'inexistente' };
  if (cv.cancelado) return { valido: false, motivo: 'cancelado' };
  if (cv.usado_em) return { valido: false, motivo: 'usado' };
  return { valido: true };
}

async function listarConvites(env) {
  const { results } = await env.DB.prepare(
    'SELECT token, descricao, criado_em, criado_por, usado_em, candidato_id, cancelado FROM convites ORDER BY criado_em DESC LIMIT 200'
  ).all();
  return json({ convites: results });
}

async function criarConvite(env, user, body) {
  const token = novoId('');
  const descricao = String((body && body.descricao) || '').trim().slice(0, 120);
  await env.DB.prepare('INSERT INTO convites (token, descricao, criado_em, criado_por) VALUES (?, ?, ?, ?)')
    .bind(token, descricao, new Date().toISOString(), user.nome || user.usuario).run();
  return json({ token });
}

async function cancelarConvite(env, body) {
  const token = String((body && body.token) || '');
  if (!idValido(token)) return erro('Link inválido.');
  await env.DB.prepare('UPDATE convites SET cancelado = 1 WHERE token = ? AND usado_em IS NULL').bind(token).run();
  return json({ ok: true });
}

async function cadastroPublico(env, body) {
  const c = body && body.candidato;
  if (!c || typeof c !== 'object' || !String(c.nome || '').trim()) return erro('Cadastro inválido.');

  // o link só pode ser usado uma vez: marca como usado antes de gravar
  const token = String(body.convite || '');
  if (!idValido(token)) return erro('Este link de cadastro não é válido.', 410);
  const agora = new Date().toISOString();
  const marcou = await env.DB.prepare(
    'UPDATE convites SET usado_em = ? WHERE token = ? AND usado_em IS NULL AND cancelado = 0'
  ).bind(agora, token).run();
  if (!marcou.meta || marcou.meta.changes !== 1) return erro('Este link já foi utilizado ou expirou.', 410);

  try {
    return await gravarCandidatoPublico(env, c, token);
  } catch (e) {
    await env.DB.prepare('UPDATE convites SET usado_em = NULL WHERE token = ?').bind(token).run(); // libera o link se deu erro
    throw e;
  }
}

async function gravarCandidatoPublico(env, c, token) {
  c.id = novoId('c_');
  c.avaliacao = null;
  c.criadoEm = new Date().toISOString();
  if (typeof c.curriculoDataUrl === 'string' && c.curriculoDataUrl.startsWith('data:')) {
    const fid = novoId('f_');
    await salvarArquivo(env, fid, c.curriculoDataUrl);
    c.curriculoDataUrl = 'arquivo:' + fid;
  } else {
    c.curriculoDataUrl = '';
  }
  await env.DB.prepare("INSERT INTO registros (tipo, id, dados, atualizado_em) VALUES ('candidato', ?, ?, ?)")
    .bind(c.id, JSON.stringify(c), c.criadoEm).run();
  await env.DB.prepare('UPDATE convites SET candidato_id = ? WHERE token = ?').bind(c.id, token).run();
  return json({ ok: true, id: c.id });
}

async function configPublica(env) {
  const r = await env.DB.prepare("SELECT dados FROM registros WHERE tipo = 'config' AND id = 'geral'").first();
  if (!r) return json({});
  const cfg = JSON.parse(r.dados);
  let systemLogo = '';
  const ref = String(cfg.systemLogo || '');
  if (ref.startsWith('arquivo:')) systemLogo = (await lerArquivo(env, ref.slice(8))) || '';
  return json({
    appTitle: cfg.appTitle || '',
    empresa: (cfg.company && cfg.company.nome) || '',
    systemLogo
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, '');

    try {
      if (p === '' || p === '/api') return json({ ok: true, sistema: 'Plataforma de Candidatos' });

      // públicas
      if (p === '/api/login' && request.method === 'POST') return await login(env, await request.json());
      if (p === '/api/publico/config' && request.method === 'GET') return await configPublica(env);
      if (p === '/api/publico/candidato' && request.method === 'POST') return await cadastroPublico(env, await request.json());
      const mc = p.match(/^\/api\/publico\/convite\/([A-Za-z0-9_-]+)$/);
      if (mc && request.method === 'GET') return json(await statusConvite(env, mc[1]));

      // precisam de login
      const user = await usuarioDaSessao(env, request);
      if (!user) return erro('Sessão expirada. Entre novamente.', 401);

      if (p === '/api/sessao') return json({ usuario: { id: user.id, nome: user.nome, usuario: user.usuario, perfil: user.perfil, precisaTrocarSenha: user.precisaTrocarSenha } });
      if (p === '/api/logout' && request.method === 'POST') {
        await env.DB.prepare('DELETE FROM sessoes WHERE token = ?').bind(user.token).run();
        return json({ ok: true });
      }
      if (p === '/api/dados' && request.method === 'GET') return await dados(env);
      if (p === '/api/sync' && request.method === 'POST') return await sync(env, user, await request.json());
      if (p === '/api/verificar-senha' && request.method === 'POST') return await verificarSenha(env, user, await request.json());
      if (p === '/api/trocar-senha' && request.method === 'POST') return await trocarSenha(env, user, await request.json());

      if (p.startsWith('/api/convites')) {
        if (user.perfil !== 'Administrador' && user.perfil !== 'Membro') return erro('Você não tem permissão para gerar links de cadastro.', 403);
        if (p === '/api/convites' && request.method === 'GET') return await listarConvites(env);
        if (p === '/api/convites' && request.method === 'POST') return await criarConvite(env, user, await request.json());
        if (p === '/api/convites/cancelar' && request.method === 'POST') return await cancelarConvite(env, await request.json());
      }

      const m = p.match(/^\/api\/arquivo\/([A-Za-z0-9_-]+)$/);
      if (m && request.method === 'GET') {
        const dataUrl = await lerArquivo(env, m[1]);
        if (!dataUrl) return erro('Arquivo não encontrado.', 404);
        // arquivo é imutável (cada upload gera um id novo), então pode guardar em cache por bastante tempo
        return new Response(JSON.stringify({ dataUrl }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'public, max-age=31536000, immutable',
            ...CORS
          }
        });
      }

      return erro('Rota não encontrada.', 404);
    } catch (e) {
      return erro(e.message || 'Erro interno.', 500);
    }
  }
};

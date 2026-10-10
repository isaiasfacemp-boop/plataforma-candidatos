-- Banco D1: plataforma_candidatos
-- Cole tudo no Console do banco e clique em Execute.

-- Candidatos, usuários, mensagens e configurações (cada item é uma linha em JSON)
CREATE TABLE IF NOT EXISTS registros (
  tipo TEXT NOT NULL,          -- candidato | usuario | mensagem | config
  id TEXT NOT NULL,
  dados TEXT NOT NULL,
  atualizado_em TEXT,
  PRIMARY KEY (tipo, id)
);

-- Arquivos (currículos, pareceres, logos), divididos em partes por causa do limite de tamanho do D1
CREATE TABLE IF NOT EXISTS arquivos_partes (
  arquivo_id TEXT NOT NULL,
  parte INTEGER NOT NULL,
  conteudo TEXT NOT NULL,
  PRIMARY KEY (arquivo_id, parte)
);

-- Sessões de login
CREATE TABLE IF NOT EXISTS sessoes (
  token TEXT PRIMARY KEY,
  usuario_id TEXT NOT NULL,
  criado_em TEXT NOT NULL
);

-- Links de cadastro de uso único
CREATE TABLE IF NOT EXISTS convites (
  token TEXT PRIMARY KEY,
  descricao TEXT,
  criado_em TEXT NOT NULL,
  criado_por TEXT,
  usado_em TEXT,
  candidato_id TEXT,
  cancelado INTEGER NOT NULL DEFAULT 0
);

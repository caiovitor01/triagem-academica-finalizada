/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import type {
  User,
  Ticket,
  TicketMessage,
  TriageEvaluation,
  Sector,
  UrgencyLevel,
  TicketStatus,
  TriageBenchmarkStats,
} from './src/types.ts';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'unitriagem-academic-secret-key-unama-2026';
const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'academic_tickets_db.json');

app.use(express.json());

// Initialize Gemini SDK if key is available
const geminiApiKey = process.env.GEMINI_API_KEY;
const ai = geminiApiKey ? new GoogleGenAI() : null;

// ==========================================
// Database Storage Interface
// ==========================================
interface DatabaseSchema {
  users: (User & { passwordHash: string; salt: string })[];
  tickets: Ticket[];
  triageLogs: {
    ticketId: string;
    textLength: number;
    method: 'Regras de Negócio' | 'PLN / IA Generativa Híbrida';
    predictedSector: Sector;
    predictedUrgency: UrgencyLevel;
    latencyMs: number;
    timestamp: string;
    reclassified: boolean;
  }[];
  supportRequests?: {
    id: string;
    protocol: string;
    name: string;
    email: string;
    instituicao?: string;
    subject: string;
    message: string;
    createdAt: string;
  }[];
}

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString('hex');
}

function generateToken(payload: { id: string; email: string; role: string }): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(
    JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 })
  ).toString('base64url');
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token: string): { id: string; email: string; role: string } | null {
  try {
    const [header, body, signature] = token.split('.');
    if (!header || !body || !signature) return null;
    const expected = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${header}.${body}`)
      .digest('base64url');
    if (expected !== signature) return null;
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (parsed.exp && parsed.exp < Math.floor(Date.now() / 1000)) return null;
    return parsed;
  } catch {
    return null;
  }
}

// Seed initial database state aligned with Caio Vitor's TCC research project
function getInitialDatabase(): DatabaseSchema {
  const salt1 = crypto.randomBytes(16).toString('hex');
  const salt2 = crypto.randomBytes(16).toString('hex');
  const salt3 = crypto.randomBytes(16).toString('hex');
  const salt4 = crypto.randomBytes(16).toString('hex');
  const salt5 = crypto.randomBytes(16).toString('hex');
  const defaultPass = '123456';

  const users: DatabaseSchema['users'] = [
    {
      id: 'usr-student-01',
      name: 'Caio Vitor Pinheiro Moraes',
      email: 'caio.vitor@unama.br',
      role: 'aluno',
      matricula: '04179424',
      instituicao: 'UNAMA - Universidade da Amazônia',
      curso: 'Análise e Desenvolvimento de Sistemas',
      phone: '(91) 98123-4567',
      avatarColor: 'bg-emerald-600',
      passwordHash: hashPassword(defaultPass, salt1),
      salt: salt1,
      createdAt: '2026-10-01T08:00:00.000Z',
    },
    {
      id: 'usr-student-02',
      name: 'Beatriz Ramos Silva',
      email: 'beatriz.ramos@unama.br',
      role: 'aluno',
      matricula: '04185290',
      instituicao: 'UNAMA - Universidade da Amazônia',
      curso: 'Engenharia de Software',
      phone: '(91) 98877-6655',
      avatarColor: 'bg-indigo-600',
      passwordHash: hashPassword(defaultPass, salt2),
      salt: salt2,
      createdAt: '2026-10-05T09:30:00.000Z',
    },
    {
      id: 'usr-staff-coord',
      name: 'Prof. Dr. Marcos Valente',
      email: 'coordenacao@unama.br',
      role: 'funcionario',
      matricula: 'F-88401',
      instituicao: 'UNAMA - Universidade da Amazônia',
      setor: 'Coordenação',
      cargo: 'Coordenador Acadêmico de ADS & Computação',
      phone: '(91) 3210-9001',
      avatarColor: 'bg-violet-600',
      passwordHash: hashPassword(defaultPass, salt3),
      salt: salt3,
      createdAt: '2026-09-01T08:00:00.000Z',
    },
    {
      id: 'usr-staff-fin',
      name: 'Mariana Lopes',
      email: 'financeiro@unama.br',
      role: 'funcionario',
      matricula: 'F-99214',
      instituicao: 'UNAMA - Universidade da Amazônia',
      setor: 'Financeiro',
      cargo: 'Analista de Cobrança e Bolsas FIES/PROUNI',
      phone: '(91) 3210-9002',
      avatarColor: 'bg-amber-600',
      passwordHash: hashPassword(defaultPass, salt4),
      salt: salt4,
      createdAt: '2026-09-01T08:00:00.000Z',
    },
    {
      id: 'usr-staff-sec',
      name: 'Carlos Eduardo Pontes',
      email: 'secretaria@unama.br',
      role: 'funcionario',
      matricula: 'F-77150',
      instituicao: 'UNAMA - Universidade da Amazônia',
      setor: 'Secretaria',
      cargo: 'Assistente de Registros Acadêmicos',
      phone: '(91) 3210-9003',
      avatarColor: 'bg-blue-600',
      passwordHash: hashPassword(defaultPass, salt5),
      salt: salt5,
      createdAt: '2026-09-01T08:00:00.000Z',
    },
  ];

  const tickets: Ticket[] = [
    {
      id: 'TCK-2026-001',
      protocolo: '2026-ADS-001',
      studentId: 'usr-student-01',
      studentName: 'Caio Vitor Pinheiro Moraes',
      studentMatricula: '04179424',
      studentCurso: 'Análise e Desenvolvimento de Sistemas',
      studentEmail: 'caio.vitor@unama.br',
      studentPhone: '(91) 98123-4567',
      title: 'Cobrança indevida de juros em boleto já compensado',
      description:
        'Boa tarde. Meu boleto com vencimento em 10/10 foi quitado no dia 08/10 via Pix do Banco do Brasil. No entanto, o sistema financeiro do portal do aluno ainda acusa pendência e lançou multa e juros de mora indevidos, me impedindo de gerar a declaração de quitação necessária para o FIES. Solicito a baixa urgente do débito.',
      categoryTag: 'Boletos & Mensalidades',
      setor: 'Financeiro',
      setorOriginal: 'Financeiro',
      urgencia: 'Alta',
      urgenciaOriginal: 'Alta',
      status: 'Em Atendimento',
      triage: {
        setor: 'Financeiro',
        urgencia: 'Alta',
        confianca: 96,
        metodo: 'Regras de Negócio',
        latenciaMs: 14,
        justificativaUrgencia:
          'Impacto financeiro com iminência de bloqueio de documentação e bolsa estudantil governamental (FIES).',
        justificativaSetor:
          'Termos financeiros expressos identificados: boleto, quitado, pix, multa, juros de mora, baixa do débito.',
        palavrasChaveDetectadas: ['boleto', 'juros', 'multa', 'fies', 'quitação', 'financeiro'],
        orientacaoPreliminar:
          'Solicitar o comprovante com autenticação bancária digital para verificação de compensação no sistema bancário.',
        slaEstimadoHoras: 24,
      },
      assignedStaffId: 'usr-staff-fin',
      assignedStaffName: 'Mariana Lopes',
      createdAt: '2026-11-01T14:15:00.000Z',
      updatedAt: '2026-11-02T10:00:00.000Z',
      messages: [
        {
          id: 'msg-01',
          ticketId: 'TCK-2026-001',
          senderId: 'usr-student-01',
          senderName: 'Caio Vitor Pinheiro Moraes',
          senderRole: 'aluno',
          message:
            'Boa tarde. Meu boleto com vencimento em 10/10 foi quitado no dia 08/10 via Pix do Banco do Brasil. No entanto, o sistema financeiro do portal do aluno ainda acusa pendência e lançou multa e juros de mora indevidos, me impedindo de gerar a declaração de quitação necessária para o FIES. Solicito a baixa urgente do débito.',
          isInternalNote: false,
          createdAt: '2026-11-01T14:15:00.000Z',
        },
        {
          id: 'msg-02',
          ticketId: 'TCK-2026-001',
          senderId: 'usr-staff-fin',
          senderName: 'Mariana Lopes',
          senderRole: 'funcionario',
          message:
            'Olá Caio! Já localizei o seu chamado. Estou verificando a conciliação bancária do lote do dia 08/10. Em instantes faremos o estorno manual dos encargos indevidos.',
          isInternalNote: false,
          createdAt: '2026-11-02T10:00:00.000Z',
        },
      ],
    },
    {
      id: 'TCK-2026-002',
      protocolo: '2026-ADS-002',
      studentId: 'usr-student-02',
      studentName: 'Beatriz Ramos Silva',
      studentMatricula: '04185290',
      studentCurso: 'Engenharia de Software',
      studentEmail: 'beatriz.ramos@unama.br',
      studentPhone: '(91) 98877-6655',
      title: 'Emissão urgente de Histórico Escolar oficial para contratação de estágio',
      description:
        'Passei no processo seletivo da IBM e o departamento de RH exige meu histórico escolar oficial assinado digitalmente até amanhã às 17h, caso contrário serei desclassificada do processo seletivo de estágio remunerado. Por favor, peço urgência máxima na emissão.',
      categoryTag: 'Documentação Acadêmica',
      setor: 'Secretaria',
      setorOriginal: 'Secretaria',
      urgencia: 'Crítica',
      urgenciaOriginal: 'Crítica',
      status: 'Aberto',
      triage: {
        setor: 'Secretaria',
        urgencia: 'Crítica',
        confianca: 94,
        metodo: 'PLN / IA Generativa Híbrida',
        latenciaMs: 382,
        justificativaUrgencia:
          'Risco crítico irreversível de perda de oportunidade de estágio/emprego com prazo explícito fatal de 24 horas.',
        justificativaSetor:
          'Emissão de documentos oficiais escolares assinados é competência exclusiva da Secretaria Acadêmica.',
        palavrasChaveDetectadas: ['histórico escolar', 'urgente', 'estágio', 'desclassificada', 'prazo amanhã'],
        orientacaoPreliminar:
          'Prioridade máxima da fila da secretaria. Emitir documento com chave de autenticidade no sistema ICP-Brasil.',
        slaEstimadoHoras: 4,
      },
      createdAt: '2026-11-04T09:20:00.000Z',
      updatedAt: '2026-11-04T09:20:00.000Z',
      messages: [
        {
          id: 'msg-03',
          ticketId: 'TCK-2026-002',
          senderId: 'usr-student-02',
          senderName: 'Beatriz Ramos Silva',
          senderRole: 'aluno',
          message:
            'Passei no processo seletivo da IBM e o departamento de RH exige meu histórico escolar oficial assinado digitalmente até amanhã às 17h, caso contrário serei desclassificada do processo seletivo de estágio remunerado. Por favor, peço urgência máxima na emissão.',
          isInternalNote: false,
          createdAt: '2026-11-04T09:20:00.000Z',
        },
      ],
    },
    {
      id: 'TCK-2026-003',
      protocolo: '2026-ADS-003',
      studentId: 'usr-student-01',
      studentName: 'Caio Vitor Pinheiro Moraes',
      studentMatricula: '04179424',
      studentCurso: 'Análise e Desenvolvimento de Sistemas',
      studentEmail: 'caio.vitor@unama.br',
      title: 'Aproveitamento de estudos de disciplina de Engenharia de Software I cursada em outra faculdade',
      description:
        'Gostaria de requerer o aproveitamento de estudos e dispensa da disciplina de Engenharia de Software I. Já cursei matéria idêntica com carga horária de 80h na UFPA, com aproveitamento e nota 9.0. Já possuo a ementa oficial e histórico em mãos.',
      categoryTag: 'Grade Curricular & Dispensa',
      setor: 'Coordenação',
      setorOriginal: 'Coordenação',
      urgencia: 'Média',
      urgenciaOriginal: 'Média',
      status: 'Aberto',
      triage: {
        setor: 'Coordenação',
        urgencia: 'Média',
        confianca: 92,
        metodo: 'Regras de Negócio',
        latenciaMs: 18,
        justificativaUrgencia:
          'Trâmite acadêmico padrão sem risco imediato de perda de prazo letivo.',
        justificativaSetor:
          'Análise de ementa e equivalência pedagógica curricular é de atribuição do Coordenador do Curso.',
        palavrasChaveDetectadas: ['aproveitamento de estudos', 'dispensa', 'disciplina', 'ementa', 'equivalência'],
        orientacaoPreliminar:
          'Instruir o aluno a anexar o programa da disciplina carimbado pela IES de origem.',
        slaEstimadoHoras: 48,
      },
      assignedStaffId: 'usr-staff-coord',
      assignedStaffName: 'Prof. Dr. Marcos Valente',
      createdAt: '2026-11-03T16:00:00.000Z',
      updatedAt: '2026-11-03T16:00:00.000Z',
      messages: [
        {
          id: 'msg-04',
          ticketId: 'TCK-2026-003',
          senderId: 'usr-student-01',
          senderName: 'Caio Vitor Pinheiro Moraes',
          senderRole: 'aluno',
          message:
            'Gostaria de requerer o aproveitamento de estudos e dispensa da disciplina de Engenharia de Software I. Já cursei matéria idêntica com carga horária de 80h na UFPA, com aproveitamento e nota 9.0. Já possuo a ementa oficial e histórico em mãos.',
          isInternalNote: false,
          createdAt: '2026-11-03T16:00:00.000Z',
        },
      ],
    },
    {
      id: 'TCK-2026-004',
      protocolo: '2026-ADS-004',
      studentId: 'usr-student-02',
      studentName: 'Beatriz Ramos Silva',
      studentMatricula: '04185290',
      studentCurso: 'Engenharia de Software',
      studentEmail: 'beatriz.ramos@unama.br',
      title: 'Dúvida sobre calendário acadêmico para entrega de horas complementares',
      description:
        'Olá! Gostaria de saber até qual semestre posso enviar os certificados de cursos livres e palestras para validar as atividades complementares obrigatórias do curso.',
      categoryTag: 'Dúvidas Gerais',
      setor: 'Coordenação',
      setorOriginal: 'Coordenação',
      urgencia: 'Baixa',
      urgenciaOriginal: 'Baixa',
      status: 'Resolvido',
      triage: {
        setor: 'Coordenação',
        urgencia: 'Baixa',
        confianca: 89,
        metodo: 'Regras de Negócio',
        latenciaMs: 12,
        justificativaUrgencia:
          'Dúvida de caráter meramente informativo, sem prazo perene ou penalidade acadêmica corrente.',
        justificativaSetor:
          'Orientação sobre matriz de horas complementares e regimento pedagógico do curso.',
        palavrasChaveDetectadas: ['horas complementares', 'calendário', 'atividades complementares', 'dúvida'],
        orientacaoPreliminar:
          'Informar o manual de atividades complementares disponível no portal.',
        slaEstimadoHoras: 72,
      },
      assignedStaffId: 'usr-staff-coord',
      assignedStaffName: 'Prof. Dr. Marcos Valente',
      createdAt: '2026-10-28T11:00:00.000Z',
      updatedAt: '2026-10-29T15:30:00.000Z',
      resolvedAt: '2026-10-29T15:30:00.000Z',
      messages: [
        {
          id: 'msg-05',
          ticketId: 'TCK-2026-004',
          senderId: 'usr-student-02',
          senderName: 'Beatriz Ramos Silva',
          senderRole: 'aluno',
          message:
            'Olá! Gostaria de saber até qual semestre posso enviar os certificados de cursos livres e palestras para validar as atividades complementares obrigatórias do curso.',
          isInternalNote: false,
          createdAt: '2026-10-28T11:00:00.000Z',
        },
        {
          id: 'msg-06',
          ticketId: 'TCK-2026-004',
          senderId: 'usr-staff-coord',
          senderName: 'Prof. Dr. Marcos Valente',
          senderRole: 'funcionario',
          message:
            'Olá Beatriz! Os certificados de horas complementares podem ser submetidos via portal até o penúltimo mês do seu último semestre letivo antes da colação de grau. Recomendo não deixar para o final!',
          isInternalNote: false,
          createdAt: '2026-10-29T15:30:00.000Z',
        },
      ],
    },
  ];

  const triageLogs: DatabaseSchema['triageLogs'] = [
    {
      ticketId: 'TCK-2026-001',
      textLength: 320,
      method: 'Regras de Negócio',
      predictedSector: 'Financeiro',
      predictedUrgency: 'Alta',
      latencyMs: 14,
      timestamp: '2026-11-01T14:15:00.000Z',
      reclassified: false,
    },
    {
      ticketId: 'TCK-2026-002',
      textLength: 254,
      method: 'PLN / IA Generativa Híbrida',
      predictedSector: 'Secretaria',
      predictedUrgency: 'Crítica',
      latencyMs: 382,
      timestamp: '2026-11-04T09:20:00.000Z',
      reclassified: false,
    },
    {
      ticketId: 'TCK-2026-003',
      textLength: 260,
      method: 'Regras de Negócio',
      predictedSector: 'Coordenação',
      predictedUrgency: 'Média',
      latencyMs: 18,
      timestamp: '2026-11-03T16:00:00.000Z',
      reclassified: false,
    },
    {
      ticketId: 'TCK-2026-004',
      textLength: 178,
      method: 'Regras de Negócio',
      predictedSector: 'Coordenação',
      predictedUrgency: 'Baixa',
      latencyMs: 12,
      timestamp: '2026-10-28T11:00:00.000Z',
      reclassified: false,
    },
  ];

  return { users, tickets, triageLogs };
}

function loadDatabase(): DatabaseSchema {
  ensureDataDir();
  if (!fs.existsSync(DB_FILE)) {
    const initial = getInitialDatabase();
    saveDatabase(initial);
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    const initial = getInitialDatabase();
    saveDatabase(initial);
    return initial;
  }
}

function saveDatabase(db: DatabaseSchema) {
  ensureDataDir();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
}

// ==========================================
// Hybrid Triage Engine (Regras + PLN/LLM)
// ==========================================

const SECTOR_KEYWORDS: Record<Sector, string[]> = {
  Financeiro: [
    'boleto', 'boletos', 'mensalidade', 'mensalidades', 'juros', 'multa', 'pagamento', 'pagamentos',
    'paguei', 'pix', 'acordo', 'parcelamento', 'desconto', 'bolsa', 'fies', 'prouni',
    'quitação', 'débito', 'cobrança', 'financeiro', 'tesouraria', 'estorno', 'reembolso',
    'valor indevido', 'duplicidade', 'banco', 'comprovante de pagamento'
  ],
  Secretaria: [
    'histórico', 'historico', 'declaração', 'declaracao', 'matrícula', 'matricula', 'rematrícula',
    'rematricula', 'trancamento', 'trancar', 'cancelamento', 'cancelar curso', 'transferência',
    'diploma', 'certificado', 'carteirinha', 'colação de grau', 'documento', 'documentos',
    'rg', 'cpf', 'atestado de matrícula', 'atestado médico', 'secretaria'
  ],
  Coordenação: [
    'dispensa', 'aproveitamento', 'equivalência', 'equivalencia', 'grade', 'ementa', 'matriz curricular',
    'pré-requisito', 'prerequisito', 'choque de horário', 'tcc', 'monografia', 'estágio supervisionado',
    'estagio', 'recurso de nota', 'revisão de prova', 'revisao de prova', 'falta', 'faltas',
    'professor', 'professora', 'docente', 'coordenador', 'coordenadora', 'coordenação'
  ],
};

const CRITICAL_KEYWORDS = [
  'urgente', 'urgência', 'emergência', 'perder a vaga', 'perder o estágio', 'perder bolsa',
  'desclassificado', 'desclassificada', 'prazo hoje', 'último dia', 'expira hoje',
  'bloqueado no sistema', 'impedimento de colação', 'risco de jubilamento', 'amanhã'
];

const HIGH_KEYWORDS = [
  'prazo', 'vencimento', 'juros', 'esta semana', 'processo seletivo', 'bloqueio',
  'impedindo', 'preciso com pressa', 'até sexta', 'multa indevida', 'concurso'
];

const LOW_KEYWORDS = [
  'dúvida simples', 'informação', 'curiosidade', 'quando abre', 'calendário',
  'próximo ano', 'horas complementares', 'optativas', 'palestra', 'esclarecimento'
];

/**
 * Stage 1: Fast Rule-Based Classifier (0 ms latency, 0 compute cost)
 */
function evaluateByRules(title: string, description: string): {
  setor: Sector;
  urgencia: UrgencyLevel;
  confidence: number;
  matchedKeywords: string[];
  isConfident: boolean;
  reasonSetor: string;
  reasonUrgencia: string;
} {
  const fullText = `${title} ${description}`.toLowerCase();

  // Score sectors
  const sectorScores: Record<Sector, { score: number; keywords: string[] }> = {
    Financeiro: { score: 0, keywords: [] },
    Secretaria: { score: 0, keywords: [] },
    Coordenação: { score: 0, keywords: [] },
  };

  (Object.keys(SECTOR_KEYWORDS) as Sector[]).forEach((sec) => {
    SECTOR_KEYWORDS[sec].forEach((kw) => {
      if (fullText.includes(kw)) {
        // give extra weight if keyword appears in title
        const weight = title.toLowerCase().includes(kw) ? 3 : 1;
        sectorScores[sec].score += weight;
        sectorScores[sec].keywords.push(kw);
      }
    });
  });

  let bestSector: Sector = 'Secretaria';
  let maxScore = -1;
  let secondScore = -1;

  for (const sec of ['Financeiro', 'Secretaria', 'Coordenação'] as Sector[]) {
    if (sectorScores[sec].score > maxScore) {
      secondScore = maxScore;
      maxScore = sectorScores[sec].score;
      bestSector = sec;
    } else if (sectorScores[sec].score > secondScore) {
      secondScore = sectorScores[sec].score;
    }
  }

  // Evaluate Urgency by rule patterns
  let urgencia: UrgencyLevel = 'Média';
  const matchedUrgencies: string[] = [];
  let reasonUrgencia = 'Demanda acadêmica regular com trâmite padrão do setor.';

  const hasCritical = CRITICAL_KEYWORDS.filter((k) => fullText.includes(k));
  const hasHigh = HIGH_KEYWORDS.filter((k) => fullText.includes(k));
  const hasLow = LOW_KEYWORDS.filter((k) => fullText.includes(k));

  if (hasCritical.length > 0) {
    urgencia = 'Crítica';
    matchedUrgencies.push(...hasCritical);
    reasonUrgencia = `Identificados termos de alta severidade/risco de perda irreversível de prazo ou vaga (${hasCritical.slice(0, 3).join(', ')}).`;
  } else if (hasHigh.length > 0) {
    urgencia = 'Alta';
    matchedUrgencies.push(...hasHigh);
    reasonUrgencia = `Impacto direto a curto prazo com prazo sensível identificado (${hasHigh.slice(0, 3).join(', ')}).`;
  } else if (hasLow.length > 0 && maxScore <= 2) {
    urgencia = 'Baixa';
    matchedUrgencies.push(...hasLow);
    reasonUrgencia = `Solicitação de caráter predominantemente informativo ou de planejamento futuro (${hasLow.slice(0, 3).join(', ')}).`;
  }

  // Calculate rule confidence
  let confidence = 50;
  if (maxScore >= 4 && maxScore - secondScore >= 2) {
    confidence = 94;
  } else if (maxScore >= 2 && maxScore > secondScore) {
    confidence = 86;
  } else if (maxScore >= 1 && maxScore > secondScore) {
    confidence = 72;
  } else {
    confidence = 45; // Ambiguous or unknown words, triggers Stage 2!
  }

  const isConfident = confidence >= 80;
  const matchedKeywords = Array.from(
    new Set([...sectorScores[bestSector].keywords, ...matchedUrgencies])
  );

  return {
    setor: bestSector,
    urgencia,
    confidence,
    matchedKeywords,
    isConfident,
    reasonSetor: `Correspondência exata de regras léxicas do setor com pontuação ponderada ${maxScore} para ${bestSector}.`,
    reasonUrgencia,
  };
}

/**
 * Stage 2: NLP / LLM Semantic Evaluation via Gemini API
 * Aligned with the Hybrid Architecture of Caio's TCC
 */
async function evaluateByGemini(
  title: string,
  description: string,
  ruleResult: ReturnType<typeof evaluateByRules>
): Promise<TriageEvaluation> {
  const startTime = performance.now();

  if (!ai) {
    // If no API key configured, fallback to rule engine enhanced heuristics
    const latenciaMs = Math.max(1, Math.round(performance.now() - startTime));
    const slaEstimadoHoras =
      ruleResult.urgencia === 'Crítica'
        ? 4
        : ruleResult.urgencia === 'Alta'
        ? 24
        : ruleResult.urgencia === 'Média'
        ? 48
        : 72;
    return {
      setor: ruleResult.setor,
      urgencia: ruleResult.urgencia,
      confianca: ruleResult.confidence,
      metodo: 'Regras de Negócio',
      latenciaMs,
      justificativaUrgencia: ruleResult.reasonUrgencia,
      justificativaSetor: ruleResult.reasonSetor,
      palavrasChaveDetectadas: ruleResult.matchedKeywords,
      orientacaoPreliminar: `Encaminhado automaticamente via motor de regras para o time de ${ruleResult.setor}.`,
      slaEstimadoHoras,
    };
  }

  try {
    const prompt = `Você é o módulo de Processamento de Linguagem Natural (PLN) da API híbrida de triagem acadêmica descrita no projeto de pesquisa de Caio Vitor Pinheiro Moraes (UNAMA).
Sua missão é classificar o chamado estudantil com alta precisão e baixo tempo de inferência.

DADOS DO CHAMADO:
Título: "${title}"
Descrição: "${description}"

REGRAS DE CLASSIFICAÇÃO:
1. SETORES DISPONÍVEIS:
   - "Financeiro": boletos, taxas, parcelamento, FIES, PROUNI, descontos, quitação, juros, comprovantes bancários.
   - "Secretaria": histórico escolar, declarações oficiais, trancamento, rematrícula, certificados, diplomas, atestados médicos, colação de grau, documentação civil.
   - "Coordenação": equivalência de disciplinas, dispensa, ajuste de grade, aproveitamento de estudos, ementas, pré-requisitos, recurso de nota/faltas, TCC, estágio supervisionado.

2. AVALIAÇÃO DA GRAVIDADE DO PROBLEMA (URGÊNCIA):
   - "Crítica" (Gravidade Máxima): Risco imediato ou dano irreversível ao estudante (perda iminente de vaga de estágio/trabalho em 24h, perda de bolsa FIES/PROUNI, cancelamento involuntário de matrícula, posse em concurso público, erro de sistema impedindo realização de prova). SLA: 4 horas.
   - "Alta" (Gravidade Alta): Impacto acadêmico ou financeiro direto iminente a curto prazo (documentação para processo seletivo esta semana, contestação de juros/multa indevida acumulando, aditamento de contrato com prazo próximo). SLA: 24 horas.
   - "Média" (Gravidade Regular): Demandas rotineiras do semestre sem risco iminente de penalidade (aproveitamento regular de matérias, declaração simples, ajuste de grade curricular no período normal). SLA: 48 horas.
   - "Baixa" (Gravidade Mínima): Solicitações puramente informativas, dúvidas sobre calendário acadêmico, horas complementares sem prazo fixado. SLA: 72 horas.

Responda ESTRITAMENTE em formato JSON com o esquema solicitado.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            setor: {
              type: Type.STRING,
              enum: ['Financeiro', 'Secretaria', 'Coordenação'],
            },
            urgencia: {
              type: Type.STRING,
              enum: ['Baixa', 'Média', 'Alta', 'Crítica'],
            },
            confianca: {
              type: Type.NUMBER,
              description: 'Porcentagem de confiança de 0 a 100',
            },
            justificativaUrgencia: {
              type: Type.STRING,
              description: 'Explicação concisa do grau de gravidade e impacto no aluno',
            },
            justificativaSetor: {
              type: Type.STRING,
              description: 'Por que este setor acadêmico específico é o responsável',
            },
            palavrasChaveDetectadas: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            orientacaoPreliminar: {
              type: Type.STRING,
              description: 'Primeira instrução prática recomendada ao atendente ou aluno',
            },
            slaEstimadoHoras: {
              type: Type.NUMBER,
              description: 'SLA máximo de resposta em horas (4, 24, 48 ou 72)',
            },
          },
          required: [
            'setor',
            'urgencia',
            'confianca',
            'justificativaUrgencia',
            'justificativaSetor',
            'palavrasChaveDetectadas',
            'orientacaoPreliminar',
            'slaEstimadoHoras',
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    const latenciaMs = Math.round(performance.now() - startTime);

    return {
      setor: (parsed.setor as Sector) || ruleResult.setor,
      urgencia: (parsed.urgencia as UrgencyLevel) || ruleResult.urgencia,
      confianca: Math.min(100, Math.max(70, Number(parsed.confianca) || 92)),
      metodo: 'PLN / IA Generativa Híbrida',
      latenciaMs,
      justificativaUrgencia:
        parsed.justificativaUrgencia || ruleResult.reasonUrgencia,
      justificativaSetor:
        parsed.justificativaSetor || ruleResult.reasonSetor,
      palavrasChaveDetectadas: Array.isArray(parsed.palavrasChaveDetectadas)
        ? parsed.palavrasChaveDetectadas
        : ruleResult.matchedKeywords,
      orientacaoPreliminar:
        parsed.orientacaoPreliminar || 'Direcionado com sucesso pelo módulo inteligente.',
      slaEstimadoHoras: Number(parsed.slaEstimadoHoras) || 24,
    };
  } catch (err) {
    console.error('Gemini NLP triage error, falling back to rule engine:', err);
    const latenciaMs = Math.round(performance.now() - startTime);
    const slaEstimadoHoras =
      ruleResult.urgencia === 'Crítica'
        ? 4
        : ruleResult.urgencia === 'Alta'
        ? 24
        : ruleResult.urgencia === 'Média'
        ? 48
        : 72;
    return {
      setor: ruleResult.setor,
      urgencia: ruleResult.urgencia,
      confianca: ruleResult.confidence,
      metodo: 'Regras de Negócio',
      latenciaMs: Math.max(5, latenciaMs),
      justificativaUrgencia: ruleResult.reasonUrgencia,
      justificativaSetor: ruleResult.reasonSetor,
      palavrasChaveDetectadas: ruleResult.matchedKeywords,
      orientacaoPreliminar: 'Direcionamento executado via regras determinísticas.',
      slaEstimadoHoras,
    };
  }
}

/**
 * Hybrid Triage Orchestrator (Sprint 2 & 3 Architecture)
 * 1. Executes rule evaluation.
 * 2. If rules have high certainty (> 82%), immediately returns with low latency.
 * 3. If ambiguous, triggers Stage 2 Gemini NLP for context understanding.
 */
async function performHybridTriage(
  title: string,
  description: string
): Promise<TriageEvaluation> {
  const ruleStart = performance.now();
  const ruleResult = evaluateByRules(title, description);

  // If rule is confident and there is no strong ambiguity, return immediate fast result
  if (ruleResult.isConfident && !description.toLowerCase().includes('porém') && !description.toLowerCase().includes('mas')) {
    const latenciaMs = Math.max(1, Math.round(performance.now() - ruleStart));
    const slaEstimadoHoras =
      ruleResult.urgencia === 'Crítica'
        ? 4
        : ruleResult.urgencia === 'Alta'
        ? 24
        : ruleResult.urgencia === 'Média'
        ? 48
        : 72;

    return {
      setor: ruleResult.setor,
      urgencia: ruleResult.urgencia,
      confianca: ruleResult.confidence,
      metodo: 'Regras de Negócio',
      latenciaMs,
      justificativaUrgencia: ruleResult.reasonUrgencia,
      justificativaSetor: ruleResult.reasonSetor,
      palavrasChaveDetectadas: ruleResult.matchedKeywords,
      orientacaoPreliminar: `Direcionado via regras rápidas de negócio com atendimento em até ${slaEstimadoHoras}h.`,
      slaEstimadoHoras,
    };
  }

  // Engage Stage 2: NLP/LLM
  return await evaluateByGemini(title, description, ruleResult);
}

// ==========================================
// Authentication Middleware
// ==========================================
function authenticate(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Acesso não autorizado. Token ausente.' });
    return;
  }
  const token = authHeader.substring(7);
  const decoded = verifyToken(token);
  if (!decoded) {
    res.status(401).json({ error: 'Sessão inválida ou expirada. Faça login novamente.' });
    return;
  }
  const db = loadDatabase();
  const user = db.users.find((u) => u.id === decoded.id);
  if (!user) {
    res.status(401).json({ error: 'Usuário não encontrado.' });
    return;
  }
  (req as any).user = user;
  next();
}

// ==========================================
// REST API Routes
// ==========================================

// Register
app.post('/api/auth/register', (req: Request, res: Response) => {
  const { name, email, password, role, matricula, instituicao, curso, setor, cargo, phone } = req.body;

  if (!name || !email || !password || !role || !matricula) {
    res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
    return;
  }

  const db = loadDatabase();
  const existing = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    res.status(400).json({ error: 'Já existe uma conta cadastrada com este e-mail.' });
    return;
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(password, salt);
  const colors = [
    'bg-blue-600',
    'bg-emerald-600',
    'bg-indigo-600',
    'bg-violet-600',
    'bg-amber-600',
    'bg-rose-600',
    'bg-teal-600',
  ];
  const avatarColor = colors[Math.floor(Math.random() * colors.length)];

  const newUser: DatabaseSchema['users'][0] = {
    id: `usr-${Date.now()}`,
    name,
    email: email.toLowerCase(),
    role: role === 'funcionario' ? 'funcionario' : 'aluno',
    matricula,
    instituicao: (instituicao && String(instituicao).trim()) || 'UNAMA - Universidade da Amazônia',
    curso: role === 'aluno' ? curso || 'Análise e Desenvolvimento de Sistemas' : undefined,
    setor: role === 'funcionario' ? setor || 'Secretaria' : undefined,
    cargo: role === 'funcionario' ? cargo || 'Atendente Acadêmico' : undefined,
    phone: phone || '',
    avatarColor,
    passwordHash,
    salt,
    createdAt: new Date().toISOString(),
  };

  db.users.push(newUser);
  saveDatabase(db);

  const { passwordHash: _, salt: __, ...sanitizedUser } = newUser;
  const token = generateToken({
    id: newUser.id,
    email: newUser.email,
    role: newUser.role,
  });

  res.status(201).json({ user: sanitizedUser, token });
});

// Login
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: 'Informe e-mail e senha.' });
    return;
  }

  const db = loadDatabase();
  const user = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());

  if (!user) {
    res.status(401).json({ error: 'Credenciais inválidas. Verifique seu e-mail e senha.' });
    return;
  }

  const hash = hashPassword(password, user.salt);
  if (hash !== user.passwordHash) {
    res.status(401).json({ error: 'Credenciais inválidas. Verifique seu e-mail e senha.' });
    return;
  }

  const { passwordHash: _, salt: __, ...sanitizedUser } = user;
  const token = generateToken({
    id: user.id,
    email: user.email,
    role: user.role,
  });

  res.json({ user: sanitizedUser, token });
});

// Current User (me)
app.get('/api/auth/me', authenticate, (req: Request, res: Response) => {
  const user = (req as any).user;
  const { passwordHash: _, salt: __, ...sanitizedUser } = user;
  res.json({ user: sanitizedUser });
});

// Forgot / Reset Password (verifies email + academic/staff matricula)
app.post('/api/auth/reset-password', (req: Request, res: Response) => {
  const { email, matricula, newPassword } = req.body;

  if (!email || !matricula || !newPassword) {
    res.status(400).json({ error: 'Informe e-mail, matrícula e a nova senha.' });
    return;
  }

  if (String(newPassword).length < 6) {
    res.status(400).json({ error: 'A nova senha deve ter pelo menos 6 caracteres.' });
    return;
  }

  const db = loadDatabase();
  const userIndex = db.users.findIndex(
    (u) =>
      u.email.toLowerCase() === String(email).trim().toLowerCase() &&
      u.matricula.trim().toLowerCase() === String(matricula).trim().toLowerCase()
  );

  if (userIndex === -1) {
    res.status(404).json({
      error: 'Não encontramos nenhuma conta com este e-mail e matrícula combinados.',
    });
    return;
  }

  const newSalt = crypto.randomBytes(16).toString('hex');
  db.users[userIndex].salt = newSalt;
  db.users[userIndex].passwordHash = hashPassword(String(newPassword), newSalt);
  saveDatabase(db);

  res.json({
    message: 'Senha redefinida com segurança! Você já pode entrar com sua nova senha.',
  });
});

// Support Contact Request (accessible from Login screen)
app.post('/api/support-contact', (req: Request, res: Response) => {
  const { name, email, instituicao, subject, message } = req.body;

  if (!name || !email || !message) {
    res.status(400).json({ error: 'Preencha seu nome, e-mail e descreva o motivo do contato.' });
    return;
  }

  const db = loadDatabase();
  if (!Array.isArray(db.supportRequests)) {
    db.supportRequests = [];
  }

  const protocol = `SUP-2026-${String(1000 + db.supportRequests.length + 1)}`;
  const entry = {
    id: `sup-${Date.now()}`,
    protocol,
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    instituicao: instituicao ? String(instituicao).trim() : undefined,
    subject: subject ? String(subject).trim() : 'Suporte de Acesso / Conta',
    message: String(message).trim(),
    createdAt: new Date().toISOString(),
  };

  db.supportRequests.push(entry);
  saveDatabase(db);

  res.status(201).json({
    protocol,
    message: `Solicitação enviada ao suporte! Protocolo ${protocol}. Nossa equipe responderá no e-mail informado.`,
  });
});

// Create Ticket with Automated Hybrid Triage
app.post('/api/tickets', authenticate, async (req: Request, res: Response) => {
  const currentUser: User = (req as any).user;
  const { title, description, categoryTag, studentPhone } = req.body;

  if (!title || !description) {
    res.status(400).json({ error: 'O chamado precisa de um título e uma descrição detalhada.' });
    return;
  }

  try {
    // Perform Hybrid Triage
    const triage = await performHybridTriage(title, description);

    const db = loadDatabase();
    const ticketSeq = db.tickets.length + 1;
    const padSeq = String(ticketSeq).padStart(3, '0');
    const ticketId = `TCK-2026-${padSeq}`;
    const now = new Date().toISOString();

    const newTicket: Ticket = {
      id: ticketId,
      protocolo: `2026-${(currentUser.curso || 'ACAD').substring(0, 3).toUpperCase()}-${padSeq}`,
      studentId: currentUser.id,
      studentName: currentUser.name,
      studentMatricula: currentUser.matricula,
      studentCurso: currentUser.curso || 'Não informado',
      studentEmail: currentUser.email,
      studentPhone: studentPhone || currentUser.phone || '',
      title,
      description,
      categoryTag: categoryTag || 'Atendimento Geral',
      setor: triage.setor,
      setorOriginal: triage.setor,
      urgencia: triage.urgencia,
      urgenciaOriginal: triage.urgencia,
      status: 'Aberto',
      triage,
      createdAt: now,
      updatedAt: now,
      messages: [
        {
          id: `msg-${Date.now()}`,
          ticketId,
          senderId: currentUser.id,
          senderName: currentUser.name,
          senderRole: currentUser.role,
          message: description,
          isInternalNote: false,
          createdAt: now,
        },
      ],
    };

    db.tickets.unshift(newTicket);

    // Save to triage logs for scientific metrics and benchmarking
    db.triageLogs.push({
      ticketId,
      textLength: title.length + description.length,
      method: triage.metodo,
      predictedSector: triage.setor,
      predictedUrgency: triage.urgencia,
      latencyMs: triage.latenciaMs,
      timestamp: now,
      reclassified: false,
    });

    saveDatabase(db);

    res.status(201).json({ ticket: newTicket });
  } catch (error) {
    console.error('Error creating ticket:', error);
    res.status(500).json({ error: 'Erro ao processar e triar o chamado.' });
  }
});

// List Tickets (with role and sector filtering)
app.get('/api/tickets', authenticate, (req: Request, res: Response) => {
  const currentUser: User = (req as any).user;
  const { setor, status, urgencia, search } = req.query;

  const db = loadDatabase();
  let list = [...db.tickets];

  // If student, only view own tickets
  if (currentUser.role === 'aluno') {
    list = list.filter((t) => t.studentId === currentUser.id);
  } else if (currentUser.role === 'funcionario') {
    // If staff has a specific department and no query filter passed, defaults to staff sector or all
    if (setor && setor !== 'Todos') {
      list = list.filter((t) => t.setor === setor);
    }
  }

  // Filter by status
  if (status && status !== 'Todos') {
    list = list.filter((t) => t.status === status);
  }

  // Filter by urgency
  if (urgencia && urgencia !== 'Todas') {
    list = list.filter((t) => t.urgencia === urgencia);
  }

  // Keyword search
  if (search && typeof search === 'string' && search.trim() !== '') {
    const q = search.toLowerCase();
    list = list.filter(
      (t) =>
        t.title.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.protocolo.toLowerCase().includes(q) ||
        t.studentName.toLowerCase().includes(q) ||
        t.studentMatricula.toLowerCase().includes(q)
    );
  }

  res.json({ tickets: list });
});

// Get Single Ticket
app.get('/api/tickets/:id', authenticate, (req: Request, res: Response) => {
  const currentUser: User = (req as any).user;
  const { id } = req.params;

  const db = loadDatabase();
  const ticket = db.tickets.find((t) => t.id === id);

  if (!ticket) {
    res.status(404).json({ error: 'Chamado não encontrado.' });
    return;
  }

  // If student, ensure ticket belongs to student
  if (currentUser.role === 'aluno' && ticket.studentId !== currentUser.id) {
    res.status(403).json({ error: 'Você não tem permissão para visualizar este chamado.' });
    return;
  }

  // For students, filter out internal staff notes
  let sanitizedTicket = { ...ticket };
  if (currentUser.role === 'aluno') {
    sanitizedTicket.messages = ticket.messages.filter((m) => !m.isInternalNote);
  }

  res.json({ ticket: sanitizedTicket });
});

// Add message to Ticket
app.post('/api/tickets/:id/messages', authenticate, (req: Request, res: Response) => {
  const currentUser: User = (req as any).user;
  const { id } = req.params;
  const { message, isInternalNote } = req.body;

  if (!message || message.trim() === '') {
    res.status(400).json({ error: 'A mensagem não pode ser vazia.' });
    return;
  }

  const db = loadDatabase();
  const ticket = db.tickets.find((t) => t.id === id);

  if (!ticket) {
    res.status(404).json({ error: 'Chamado não encontrado.' });
    return;
  }

  if (currentUser.role === 'aluno' && ticket.studentId !== currentUser.id) {
    res.status(403).json({ error: 'Acesso negado.' });
    return;
  }

  const now = new Date().toISOString();
  const newMessage: TicketMessage = {
    id: `msg-${Date.now()}`,
    ticketId: id,
    senderId: currentUser.id,
    senderName: currentUser.name,
    senderRole: currentUser.role,
    message,
    isInternalNote: currentUser.role === 'funcionario' ? !!isInternalNote : false,
    createdAt: now,
  };

  ticket.messages.push(newMessage);
  ticket.updatedAt = now;

  // Auto transition from 'Aberto' to 'Em Atendimento' when staff replies
  if (currentUser.role === 'funcionario' && ticket.status === 'Aberto') {
    ticket.status = 'Em Atendimento';
    ticket.assignedStaffId = currentUser.id;
    ticket.assignedStaffName = currentUser.name;
  }

  saveDatabase(db);
  res.status(201).json({ message: newMessage, ticket });
});

// Update Ticket Status
app.patch('/api/tickets/:id/status', authenticate, (req: Request, res: Response) => {
  const currentUser: User = (req as any).user;
  const { id } = req.params;
  const { status } = req.body;

  const validStatuses: TicketStatus[] = [
    'Aberto',
    'Em Triagem',
    'Em Atendimento',
    'Resolvido',
    'Cancelado',
  ];
  if (!validStatuses.includes(status)) {
    res.status(400).json({ error: 'Status inválido.' });
    return;
  }

  const db = loadDatabase();
  const ticket = db.tickets.find((t) => t.id === id);

  if (!ticket) {
    res.status(404).json({ error: 'Chamado não encontrado.' });
    return;
  }

  // Student can cancel their own ticket, but cannot change staff status
  if (currentUser.role === 'aluno') {
    if (ticket.studentId !== currentUser.id || status !== 'Cancelado') {
      res.status(403).json({ error: 'Apenas funcionários podem atualizar o status de atendimento.' });
      return;
    }
  }

  const now = new Date().toISOString();
  ticket.status = status;
  ticket.updatedAt = now;
  if (status === 'Resolvido') {
    ticket.resolvedAt = now;
  }

  saveDatabase(db);
  res.json({ ticket });
});

// Reclassify Ticket (Setor or Urgency by Staff)
app.patch('/api/tickets/:id/reassign', authenticate, (req: Request, res: Response) => {
  const currentUser: User = (req as any).user;
  if (currentUser.role !== 'funcionario') {
    res.status(403).json({ error: 'Apenas atendentes e coordenadores podem reclassificar chamados.' });
    return;
  }

  const { id } = req.params;
  const { newSetor, newUrgencia, reason } = req.body;

  const db = loadDatabase();
  const ticket = db.tickets.find((t) => t.id === id);

  if (!ticket) {
    res.status(404).json({ error: 'Chamado não encontrado.' });
    return;
  }

  const now = new Date().toISOString();
  if (newSetor) ticket.setor = newSetor;
  if (newUrgencia) ticket.urgencia = newUrgencia;
  ticket.foiReclassificadoPeloAtendente = true;
  ticket.motivoReclassificacao = reason || 'Reclassificação manual pelo atendente.';
  ticket.updatedAt = now;

  // Update triage logs
  const log = db.triageLogs.find((l) => l.ticketId === id);
  if (log) {
    log.reclassified = true;
  }

  // Add system message
  ticket.messages.push({
    id: `msg-${Date.now()}`,
    ticketId: id,
    senderId: currentUser.id,
    senderName: 'Sistema de Triagem',
    senderRole: 'funcionario',
    message: `[Reclassificação] O chamado foi reatribuído para o setor "${ticket.setor}" com urgência "${ticket.urgencia}" por ${currentUser.name}. Motivo: ${ticket.motivoReclassificacao}`,
    isInternalNote: false,
    createdAt: now,
  });

  saveDatabase(db);
  res.json({ ticket });
});

// Simulation / Research Live Triage Endpoint (Allows experimenting with any text)
app.post('/api/tickets/test-triage', async (req: Request, res: Response) => {
  const { title, description } = req.body;

  if (!title || !description) {
    res.status(400).json({ error: 'Informe título e descrição para a triagem.' });
    return;
  }

  const triage = await performHybridTriage(title, description);
  res.json({ triage });
});

// Benchmarking / Metrics for Research Dashboard (Sprint 2 & 3 TCC)
app.get('/api/benchmarks', (_req: Request, res: Response) => {
  const db = loadDatabase();
  const total = db.tickets.length;
  const logs = db.triageLogs;

  const rulesCount = logs.filter((l) => l.method === 'Regras de Negócio').length;
  const plnCount = logs.filter((l) => l.method === 'PLN / IA Generativa Híbrida').length;
  const totalLatency = logs.reduce((acc, l) => acc + l.latencyMs, 0);
  const avgLatency = logs.length > 0 ? Math.round(totalLatency / logs.length) : 0;

  // Accuracy: proportion where attendants did not need to reclassify
  const reclassifiedCount = logs.filter((l) => l.reclassified).length;
  const correctCount = logs.length - reclassifiedCount;
  const accuracy = logs.length > 0 ? Math.round((correctCount / logs.length) * 100) : 95;

  const distribuicaoSetores: Record<Sector, number> = {
    Financeiro: db.tickets.filter((t) => t.setor === 'Financeiro').length,
    Secretaria: db.tickets.filter((t) => t.setor === 'Secretaria').length,
    Coordenação: db.tickets.filter((t) => t.setor === 'Coordenação').length,
  };

  const distribuicaoUrgencia: Record<UrgencyLevel, number> = {
    Crítica: db.tickets.filter((t) => t.urgencia === 'Crítica').length,
    Alta: db.tickets.filter((t) => t.urgencia === 'Alta').length,
    Média: db.tickets.filter((t) => t.urgencia === 'Média').length,
    Baixa: db.tickets.filter((t) => t.urgencia === 'Baixa').length,
  };

  const resolved = db.tickets.filter((t) => t.status === 'Resolvido').length;
  const resolutionRate = total > 0 ? Math.round((resolved / total) * 100) : 0;

  const stats: TriageBenchmarkStats = {
    totalTickets: total,
    totalAvaliadosPorRegras: rulesCount,
    totalAvaliadosPorPLN: plnCount,
    tempoMedioLatenciaMs: avgLatency,
    acuraciaEstimada: accuracy,
    distribuicaoSetores,
    distribuicaoUrgencia,
    taxaResolucao: resolutionRate,
  };

  res.json({
    stats,
    recentLogs: logs.slice(-10).reverse(),
  });
});

// Service Worker Route with root scope permissions for Chrome PWA installation
app.get('/sw.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Service-Worker-Allowed', '/');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  const swPath = path.resolve(process.cwd(), 'public', 'sw.js');
  res.sendFile(swPath);
});

// PWA Manifest Route with application/manifest+json MIME type for WebAPK minting
app.get('/manifest.json', (_req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  const manifestPath = path.resolve(process.cwd(), 'public', 'manifest.json');
  res.sendFile(manifestPath);
});

// ==========================================
// Vite Integration for Dev / Static in Prod
// ==========================================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`UniTriagem Academic Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

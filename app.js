
const button = document.getElementById("analyze");
const messageInput = document.getElementById("message");
const result = document.getElementById("result");

function normalize(text) {
  return text
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}


function detectOtpRequest(text) {
  const sentences = text
    .split(/[.!?]\s+|\n+/)
    .map(s => s.trim())
    .filter(Boolean);

  for (const sentence of sentences) {
    const normalized = normalize(sentence);

    const hasCode =
      /\b(code|otp)\b/.test(normalized);

    const hasAuthenticationContext =
      /\b(sms|verification|confirmation|authentification|securite|secret|otp)\b/.test(normalized);

    const asksToShare =
      /\b(communiquez|communique|transmettez|transmets|envoyez|envoie|donnez|donne|partagez|partage|dictez|dicte|fournissez|fournis|repondez|reponds)\b/.test(normalized);

    const isWarning =
      /\b(jamais|ne\s+\w+(?:\s+\w+){0,4}\s+pas|ne\s+pas)\b/.test(normalized);

    if (
      hasCode &&
      hasAuthenticationContext &&
      asksToShare &&
      !isWarning
    ) {
      return true;
    }
  }

  return false;
}

function analyzeMessage(message) {
  const text = normalize(message);
    
  if (detectOtpRequest(message)) {
    return {
      level: "high",
      label: "Risque élevé",
      title: "Demande suspecte de code d'authentification",
      signals: [
        "Le message demande de transmettre un code.",
        "Le code semble lié à une authentification ou vérification."
      ],
      action:
        "Ne communiquez pas ce code. Si le message prétend provenir de votre banque ou d'un service, contactez cet organisme par son application ou site officiel.",
      explanation:
        "Un code de vérification peut permettre à un tiers d'accéder à un compte ou de confirmer une opération. L'identité de l'expéditeur n'a pas été vérifiée."
    };
  }

  // Primeira versão local simplificada da detecção R3b.
  const changedNumberPattern =
    /\b(nouveau numero|change de numero|nouveau telephone|telephone casse|telephone perdu|new number|lost my phone|novo numero|troquei de numero)\b/g;

  const negatedNumberChange =
    /\b(?:je n['’]?ai pas|je n['’]?avais pas|je n['’]?ai jamais|je n['’]?avais jamais)\s+change de numero\b/;  

  const changedNumber =
    [...text.matchAll(changedNumberPattern)].some(
      match => !negatedNumberChange.test(
        text.slice(Math.max(0, match.index - 35), match.index + match[0].length)
      )
    );
    
    const moneyRequest =
    /\b(peux-tu|pourrais-tu|envoie|envoyer|virement|virer|prete|can you|send me|envia|manda|preciso)\b/.test(text) &&
    /(\d+\s*(euros?|eur|€|dollars?|\$|reais|r\$)|argent|money|dinheiro|virement|transfer)/.test(text);

  const urgent =
    /\b(urgent|urgence|tout de suite|immediatement|vite|aujourd'hui|asap|right now|urgente|agora)\b/.test(text);

  const secrecy =
    /\b(ne dis rien|n'en parle pas|garde le secret|don't tell|keep it secret|nao conte|segredo)\b/.test(text);

  const signals = [];

  if (changedNumber) {
    signals.push("Changement de numéro ou problème de téléphone mentionné.");
  }

  if (moneyRequest) {
    signals.push("Demande apparente d'argent ou de transfert.");
  }

  if (urgent) {
    signals.push("Pression temporelle détectée.");
  }

  if (secrecy) {
    signals.push("Demande de confidentialité ou de secret.");
  }

  const combinedRisk = changedNumber && moneyRequest;

  if (combinedRisk && (urgent || secrecy)) {
    return {
      level: "high",
      label: "Risque élevé",
      title: "Possible arnaque au faux proche",
      signals,
      action:
        "N'envoyez pas d'argent. Appelez votre proche sur son ancien numéro ou contactez-le par un canal indépendant.",
      explanation:
        "Plusieurs éléments concordent avec un scénario d'usurpation d'un proche."
    };
  }

  if (combinedRisk) {
    return {
      level: "medium",
      label: "Risque modéré",
      title: "Demande financière à vérifier",
      signals,
      action:
        "Confirmez l'identité de votre proche par un numéro déjà connu avant tout transfert.",
      explanation:
        "Le changement de numéro associé à une demande d'argent mérite une vérification."
    };
  }

  return {
    level: "unknown",
    label: "Analyse limitée",
    title: "Aucun scénario ciblé identifié",
    signals: [],
    action:
      "En cas de doute, vérifiez l'expéditeur par un canal indépendant avant de répondre ou d'effectuer un paiement.",
    explanation:
      "Cette version utilise des règles limitées pour détecter certains scénarios d'arnaque, notamment l'usurpation d'un proche et les demandes de codes d'authentification. L'absence de signal détecté ne garantit pas qu'un message soit sûr."
  };
}


// Context v1: interpreta apenas blocos explicitamente marcados [Message N].
// Não infere identidade, autoria nem autenticidade dos interlocutores.

function extractConversationMessages(raw) {
  const marker =
    /^\s*\[Message\s+\d+\s*(?:-\s*(Reçu|Envoyé))?\]\s*/i;

  const parts = raw
    .split(/(?=^\s*\[Message\s+\d+\s*(?:-\s*(?:Reçu|Envoyé))?\]\s*)/gim)
    .map(x => x.trim())
    .filter(Boolean);

  if (
    parts.length < 2 ||
    !parts.every(x => marker.test(x))
  ) {
    return [];
  }

  return parts.slice(0, 30).map((block, i) => {
    const match = block.match(marker);

    return {
      number: i + 1,
      direction: match[1]
        ? normalize(match[1])
        : "inconnu",
      content: block.replace(marker, "").trim()
    };
  }).filter(x => x.content);
}


function contextualSignals(content) {
  const t = normalize(content);
  const found = [];
  const numberPattern = /\b(nouveau numero|change de numero|nouveau telephone|telephone casse|telephone perdu|new number|lost my phone|novo numero|troquei de numero)\b/g;
  const negated = /\bje n['’]?ai (?:pas|jamais) change de numero\b/;
  const changedNumber = [...t.matchAll(numberPattern)].some(m => !negated.test(t.slice(Math.max(0,m.index-35),m.index+m[0].length)));
  if (changedNumber) found.push('Changement de numéro annoncé');
  const request = /\b(peux-tu|pourrais-tu|envoie|envoyer|virement|virer|prete|can you|send me|envia|manda|preciso)\b/.test(t);
  const money = /(\d+\s*(euros?|eur|€|dollars?|\$|reais|r\$)|argent|money|dinheiro|virement|transfer)/.test(t);
  if (request && money) found.push('Demande d’argent');
  if (/\b(urgent|urgence|tout de suite|immediatement|vite|aujourd'hui|asap|right now|urgente|agora)\b/.test(t)) found.push('Pression temporelle');
  if (/\b(ne dis rien|n'en parle pas|garde le secret|don't tell|keep it secret|nao conte|segredo)\b/.test(t)) found.push('Demande de secret');
  if (detectOtpRequest(content)) found.push('Demande de transmettre un code');
  return found;
}

function renderTimeline(rawMessage) {
  const messages = extractConversationMessages(rawMessage);
  if (messages.length < 2) return;
  const section = document.createElement('section');
  section.className = 'conversation-timeline';
  const h = document.createElement('h3');
  h.textContent = 'Évolution de la conversation';
  section.appendChild(h);

  let criticalFound = false;

  for (const msg of messages) {
    const entry = document.createElement('div');
    entry.className = 'timeline-entry';
    const heading = document.createElement('strong');
    heading.textContent =
    'Message ' + msg.number + ' — ' +
    (msg.direction === 'recu' ? 'Reçu' :
    msg.direction === 'envoye' ? 'Envoyé' :
    'Auteur inconnu');
    entry.appendChild(heading);
    addParagraph(entry, msg.content, 'timeline-quote');
    const signals = msg.direction === 'envoye'
        ? []
        : contextualSignals(msg.content);
    
    const critical =
      msg.direction === "recu" &&
      !criticalFound &&
      (
        signals.includes("Demande d’argent") ||
        signals.includes("Demande de transmettre un code")
      );

    if (critical) {
      criticalFound = true;
      entry.classList.add("critical-message");

      const warning = document.createElement("p");
      warning.className = "critical-warning";
      warning.textContent =
        "Point de vigilance : première demande critique reçue. Vérifiez avant d'agir.";

      entry.appendChild(warning);
    }
    
    addParagraph(
        entry,
        msg.direction === 'envoye'
        ? 'Message envoyé par vous — exclu des signaux reçus.'
        : (
            signals.length
            ? 'Indices : ' + signals.join(' · ')
            : 'Aucun indice ciblé détecté dans ce message.'
           ),             
        signals.length ? 'timeline-signals' : 'timeline-neutral'
    );

    section.appendChild(entry);
  }
  addParagraph(section, 'Les messages sont analysés dans l’ordre fourni. Les auteurs ne sont pas authentifiés ; les indices ne prouvent pas une fraude.', 'disclaimer');
  result.appendChild(section);
}

function addParagraph(parent, text, className = "") {
  const p = document.createElement("p");
  p.textContent = text;
  if (className) p.className = className;
  parent.appendChild(p);
}

function renderResult(analysis, rawMessage) {
  result.replaceChildren();
  result.hidden = false;

  const badge = document.createElement("span");
  badge.className = `risk-badge ${analysis.level}`;
  badge.textContent = analysis.label;
  result.appendChild(badge);

  const heading = document.createElement("h2");
  heading.textContent = analysis.title;
  result.appendChild(heading);

  addParagraph(result, analysis.explanation);

  if (analysis.signals.length > 0) {
    const subtitle = document.createElement("h3");
    subtitle.textContent = "Signaux détectés";
    result.appendChild(subtitle);

    const list = document.createElement("ul");

    for (const signal of analysis.signals) {
      const item = document.createElement("li");
      item.textContent = signal;
      list.appendChild(item);
    }

    result.appendChild(list);
  }

  renderTimeline(rawMessage);

  const actionTitle = document.createElement("h3");
  actionTitle.textContent = "Que faire maintenant ?";
  result.appendChild(actionTitle);

  addParagraph(result, analysis.action, "recommended-action");

  addParagraph(
    result,
    "Évaluation automatique fondée sur des règles limitées. Elle ne prouve ni la fraude ni l'authenticité du message.",
    "disclaimer"
  );
}

button.addEventListener("click", () => {
  const message = messageInput.value.trim();

  if (!message) {
    result.replaceChildren();
    result.hidden = false;
    addParagraph(result, "Veuillez saisir un message.");
    return;
  }

  
const conversation = extractConversationMessages(message);

const hasDirections = conversation.some(
  m => m.direction !== 'inconnu'
);

const textToAnalyze = hasDirections
  ? conversation
      .filter(m => m.direction === 'recu')
      .map(m => m.content)
      .join('\n')
  : message;

renderResult(analyzeMessage(textToAnalyze), message);

});


const singleModeButton = document.getElementById("mode-single");
const conversationModeButton = document.getElementById("mode-conversation");
const singleInput = document.getElementById("single-input");
const conversationInput = document.getElementById("conversation-input");
const conversationContainer = document.getElementById("conversation-messages");
const addMessageButton = document.getElementById("add-message");

let currentMode = "single";

function setMode(mode) {
  currentMode = mode;

  singleInput.hidden = mode !== "single";
  conversationInput.hidden = mode !== "conversation";

  singleModeButton.classList.toggle("active", mode === "single");
  conversationModeButton.classList.toggle("active", mode === "conversation");

  button.textContent = mode === "single"
    ? "Analyser le message"
    : "Analyser la conversation";

  result.replaceChildren();
  result.hidden = true;
}

function addConversationMessage() {
  const count = conversationContainer.children.length;

  if (count >= 30) return;

  const card = document.createElement("div");
  card.className = "conversation-card";

  const label = document.createElement("label");
  label.textContent = "Message " + (count + 1);

  const direction = document.createElement("select");

  for (const value of ["Reçu", "Envoyé"]) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    direction.appendChild(option);
  }

  const textarea = document.createElement("textarea");
  textarea.placeholder = "Texte du message...";
  textarea.maxLength = 5000;

  card.append(label, direction, textarea);
  conversationContainer.appendChild(card);
}

singleModeButton.addEventListener("click", () => setMode("single"));
conversationModeButton.addEventListener("click", () => setMode("conversation"));
addMessageButton.addEventListener("click", addConversationMessage);

addConversationMessage();
addConversationMessage();

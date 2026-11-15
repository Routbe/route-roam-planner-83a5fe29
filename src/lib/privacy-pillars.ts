/**
 * Single source for privacy claims shown by <PrivacyBadge /> and the /security Trust Center.
 * Every statement here must match the code: no hosting location or licence claims until confirmed.
 */
export type PillarId = "zk-pii" | "sovereign-identity" | "zero-trust";

export type Pillar = {
  id: PillarId;
  label: string;
  title: string;
  guarantee: string;
  how: string[];
  stored: string[];
  notStored: string[];
};

type Text = Omit<Pillar, "id">;

const NL: Record<PillarId, Text> = {
  "zk-pii": {
    label: "Zero-Knowledge PII",
    title: "Kalender zonder persoonsgegevens",
    guarantee: "Je agenda-inhoud wordt nooit opgeslagen. We bewaren alleen anonieme vrij/bezet-blokken.",
    how: [
      "Afspraken uit je gekoppelde agenda worden in het geheugen gestript: titel, beschrijving, locatie en genodigden verdwijnen vóór opslag.",
      "Externe afspraak-ID's worden met HMAC gehasht, zodat we ze niet kunnen terugkoppelen.",
      "Vrije tijd wordt per dag bewaard als anonieme UTC-bitmap van 96 kwartierblokken (bit(96)).",
    ],
    stored: ["Begin- en eindtijd van bezette blokken", "Gehashte afspraak-ID", "Bitmap met vrije kwartieren"],
    notStored: ["Titels en beschrijvingen", "Genodigden en e-mailadressen", "Locaties en vergaderlinks"],
  },
  "sovereign-identity": {
    label: "Sovereign Identity",
    title: "Jouw identiteit, jouw toestemming",
    guarantee: "Apps krijgen alleen de gegevens die jij expliciet goedkeurt. Geen trackers, geen verkoop van profieldata.",
    how: [
      "Inloggen via ROUT gebruikt OAuth 2.1 / OpenID Connect met expliciete scopes die je per app goedkeurt.",
      "Sleutels van derden (zoals betaalproviders) worden versleuteld met AES-256-GCM bewaard.",
      "Donaties via de steunpagina gaan met een EPC-QR rechtstreeks naar de bank van de maker, zonder tussenrekening.",
    ],
    stored: ["Je account en de scopes die je goedkeurde", "Versleutelde koppelingssleutels"],
    notStored: ["Advertentie- of trackingprofielen", "Kopieën van donatiegeld", "Gegevens buiten de goedgekeurde scopes"],
  },
  "zero-trust": {
    label: "Zero-Trust Isolation",
    title: "Persoonlijk en workspace strikt gescheiden",
    guarantee: "Persoonlijke gegevens en workspace-gegevens kunnen elkaar niet zien.",
    how: [
      "De actieve omgeving staat in het adres (/studio/personal of /studio/w/<naam>) en wordt bij elk verzoek op de server gecontroleerd tegen je rol.",
      "Bij het wisselen van omgeving wordt alle tijdelijk opgeslagen data in je browser gewist.",
      "Uploads krijgen pas een upload-adres na een servercontrole van plan en opslagquotum.",
    ],
    stored: ["Je rol per workspace", "Bestanden met hun eigen omgeving gelabeld"],
    notStored: ["Gedeelde caches tussen omgevingen"],
  },
};

const EN: Record<PillarId, Text> = {
  "zk-pii": {
    label: "Zero-Knowledge PII",
    title: "A calendar without personal data",
    guarantee: "Your calendar content is never stored. We only keep anonymous free/busy blocks.",
    how: [
      "Events from your connected calendar are stripped in memory: title, description, location and attendees are dropped before storage.",
      "External event IDs are hashed with HMAC so they cannot be linked back.",
      "Free time is stored per day as an anonymous UTC bitmap of 96 quarter-hour blocks (bit(96)).",
    ],
    stored: ["Start and end of busy blocks", "Hashed event ID", "Bitmap of free quarters"],
    notStored: ["Titles and descriptions", "Attendees and email addresses", "Locations and meeting links"],
  },
  "sovereign-identity": {
    label: "Sovereign Identity",
    title: "Your identity, your consent",
    guarantee: "Apps only get the data you explicitly approve. No trackers, no selling of profile data.",
    how: [
      "Sign in with ROUT uses OAuth 2.1 / OpenID Connect with explicit scopes you approve per app.",
      "Third-party keys (such as payment providers) are stored encrypted with AES-256-GCM.",
      "Support page donations go by EPC QR straight to the creator's bank, with no intermediate account.",
    ],
    stored: ["Your account and the scopes you approved", "Encrypted connection keys"],
    notStored: ["Advertising or tracking profiles", "Copies of donated money", "Data outside approved scopes"],
  },
  "zero-trust": {
    label: "Zero-Trust Isolation",
    title: "Personal and workspace strictly separated",
    guarantee: "Personal data and workspace data cannot see each other.",
    how: [
      "The active scope is in the address (/studio/personal or /studio/w/<name>) and checked on the server against your role on every request.",
      "Switching scope wipes all temporarily cached data in your browser.",
      "Uploads only get an upload address after a server check of plan and storage quota.",
    ],
    stored: ["Your role per workspace", "Files labelled with their own scope"],
    notStored: ["Shared caches between scopes"],
  },
};

const FR: Record<PillarId, Text> = {
  "zk-pii": {
    label: "Zero-Knowledge PII",
    title: "Un agenda sans données personnelles",
    guarantee: "Le contenu de votre agenda n'est jamais conservé. Nous ne gardons que des blocs anonymes libre/occupé.",
    how: [
      "Les rendez-vous de votre agenda connecté sont épurés en mémoire : titre, description, lieu et participants disparaissent avant tout stockage.",
      "Les identifiants externes des rendez-vous sont hachés avec HMAC, afin que nous ne puissions pas les relier à leur origine.",
      "Le temps libre est conservé par jour sous forme de bitmap UTC anonyme de 96 blocs d'un quart d'heure (bit(96)).",
    ],
    stored: ["Début et fin des blocs occupés", "Identifiant de rendez-vous haché", "Bitmap des quarts d'heure libres"],
    notStored: ["Titres et descriptions", "Participants et adresses e-mail", "Lieux et liens de réunion"],
  },
  "sovereign-identity": {
    label: "Sovereign Identity",
    title: "Votre identité, votre consentement",
    guarantee: "Les applications ne reçoivent que les données que vous approuvez explicitement. Aucun traceur, aucune vente de données de profil.",
    how: [
      "Se connecter avec ROUT utilise OAuth 2.1 / OpenID Connect avec des autorisations explicites que vous approuvez par application.",
      "Les clés de tiers (comme les prestataires de paiement) sont conservées chiffrées en AES-256-GCM.",
      "Les dons via la page de soutien passent par un QR EPC directement vers la banque du créateur, sans compte intermédiaire.",
    ],
    stored: ["Votre compte et les autorisations que vous avez approuvées", "Clés de connexion chiffrées"],
    notStored: ["Profils publicitaires ou de pistage", "Copies de l'argent donné", "Données hors des autorisations approuvées"],
  },
  "zero-trust": {
    label: "Zero-Trust Isolation",
    title: "Personnel et espace de travail strictement séparés",
    guarantee: "Les données personnelles et celles de l'espace de travail ne peuvent pas se voir.",
    how: [
      "L'environnement actif figure dans l'adresse (/studio/personal ou /studio/w/<nom>) et est vérifié par le serveur à chaque requête, par rapport à votre rôle.",
      "Changer d'environnement efface toutes les données mises temporairement en cache dans votre navigateur.",
      "Un téléversement ne reçoit une adresse d'envoi qu'après un contrôle serveur de l'offre et du quota de stockage.",
    ],
    stored: ["Votre rôle par espace de travail", "Des fichiers étiquetés avec leur propre environnement"],
    notStored: ["Des caches partagés entre environnements"],
  },
};

const DE: Record<PillarId, Text> = {
  "zk-pii": {
    label: "Zero-Knowledge PII",
    title: "Ein Kalender ohne personenbezogene Daten",
    guarantee: "Deine Kalenderinhalte werden nie gespeichert. Wir behalten nur anonyme Frei/Belegt-Blöcke.",
    how: [
      "Termine aus deinem verbundenen Kalender werden im Arbeitsspeicher bereinigt: Titel, Beschreibung, Ort und Teilnehmende fallen vor dem Speichern weg.",
      "Externe Termin-IDs werden mit HMAC gehasht, sodass wir sie nicht zurückverfolgen können.",
      "Freie Zeit wird pro Tag als anonyme UTC-Bitmap aus 96 Viertelstundenblöcken gespeichert (bit(96)).",
    ],
    stored: ["Beginn und Ende belegter Blöcke", "Gehashte Termin-ID", "Bitmap freier Viertelstunden"],
    notStored: ["Titel und Beschreibungen", "Teilnehmende und E-Mail-Adressen", "Orte und Meeting-Links"],
  },
  "sovereign-identity": {
    label: "Sovereign Identity",
    title: "Deine Identität, deine Einwilligung",
    guarantee: "Apps erhalten nur die Daten, die du ausdrücklich freigibst. Keine Tracker, kein Verkauf von Profildaten.",
    how: [
      "Mit ROUT anmelden nutzt OAuth 2.1 / OpenID Connect mit expliziten Berechtigungen, die du pro App freigibst.",
      "Schlüssel von Dritten (etwa Zahlungsanbietern) werden mit AES-256-GCM verschlüsselt gespeichert.",
      "Spenden über die Unterstützungsseite gehen per EPC-QR direkt auf die Bank der Person, ohne Zwischenkonto.",
    ],
    stored: ["Dein Konto und die Berechtigungen, die du freigegeben hast", "Verschlüsselte Verbindungsschlüssel"],
    notStored: ["Werbe- oder Tracking-Profile", "Kopien gespendeten Geldes", "Daten außerhalb der freigegebenen Berechtigungen"],
  },
  "zero-trust": {
    label: "Zero-Trust Isolation",
    title: "Persönlich und Workspace streng getrennt",
    guarantee: "Persönliche Daten und Workspace-Daten können einander nicht sehen.",
    how: [
      "Die aktive Umgebung steht in der Adresse (/studio/personal oder /studio/w/<name>) und wird bei jeder Anfrage auf dem Server gegen deine Rolle geprüft.",
      "Beim Wechsel der Umgebung werden alle vorübergehend zwischengespeicherten Daten in deinem Browser gelöscht.",
      "Uploads erhalten erst nach einer Serverprüfung von Tarif und Speicherkontingent eine Upload-Adresse.",
    ],
    stored: ["Deine Rolle pro Workspace", "Dateien, gekennzeichnet mit ihrer eigenen Umgebung"],
    notStored: ["Geteilte Caches zwischen Umgebungen"],
  },
};

export const PILLAR_IDS: PillarId[] = ["zk-pii", "sovereign-identity", "zero-trust"];

export const PILLAR_TEXTS: Record<"nl" | "en" | "fr" | "de", Record<PillarId, Text>> = { nl: NL, en: EN, fr: FR, de: DE };

export function pillar(id: PillarId, locale: string): Pillar {
  const lang = locale.slice(0, 2);
  const src = lang === "nl" || lang === "fr" || lang === "de" ? PILLAR_TEXTS[lang] : EN;
  return { id, ...src[id] };
}

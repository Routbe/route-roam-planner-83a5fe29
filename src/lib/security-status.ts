/**
 * Status of the booking-encryption and cryptography work shown on the /security Trust Center.
 * Every line must match the repository evidence (tests, docs/dudect-audit-report.md, verify:rls,
 * docs/HANDOVER.md). "tested" = in the code with passing tests, not a live production attestation.
 */
export type StatusLevel = "tested" | "building" | "open";
export type StatusItem = { id: string; level: StatusLevel; title: string; body: string; open?: string };
export type StatusText = {
  heading: string;
  intro: string;
  levels: Record<StatusLevel, string>;
  openLabel: string;
  items: StatusItem[];
};

type Locale4 = "nl" | "en" | "fr" | "de";

const TEXT: Record<Locale4, StatusText> = {
  nl: {
    heading: "Stand van zaken: boekingen en cryptografie",
    intro: "Per onderdeel wat in de code zit en getest is, en wat nog open staat. Een geslaagde test is geen garantie, en niets hiervan is een externe audit.",
    levels: { tested: "In de code, getest", building: "Bouwsteen, nog niet in gebruik", open: "Nog open" },
    openLabel: "Nog open",
    items: [
      { id: "sealed-bookings", level: "tested", title: "Versleutelde gastgegevens bij boeken", body: "Naam, e-mail, notitie en antwoorden worden in de browser van de gast versleuteld voor de boekingssleutel van de host (ML-KEM-1024 + X25519). De server bewaart alleen versleutelde tekst en weigert onversleutelde gastgegevens. Dat geldt ook voor het korte aanvraagformulier op profielkaarten. De host opent ze alleen op het eigen toestel.", open: "Een live boeking of aanvraag op de site en een eigen kopie voor de gast." },
      { id: "server-guards", level: "tested", title: "Elke serverfunctie controleert zelf wie er vraagt", body: "Functies voor ingelogde leden controleren de sessie op de server, niet alleen in de browser. Bewust openbare functies staan op een vaste lijst. Een automatische test faalt bij elke nieuwe functie zonder controle." },
      { id: "formal-rls", level: "tested", title: "Wiskundig bewijs van de databaseregels (Z3)", body: "Op databaseniveau 0277 zijn 1.170 van de 1.210 bewijsverplichtingen bewezen met de Z3-solver; 10 zijn bewust vrijgegeven, 30 liggen op de grens met de server, 0 zijn onbewezen.", open: "55 bekende plekken waar een unieke sleutel iets kan verraden; het inlogsysteem valt buiten dit model." },
      { id: "dudect", level: "tested", title: "Timingmeting (dudect)", body: "1.000.000 metingen per bewerking voor X25519, ML-KEM-1024, vergelijken in constante tijd, PRF naar HKDF en AES-256-GCM: alle onder de drempel |t| < 4,5 (hoogste 4,08). Dat is statistisch bewijs, geen garantie.", open: "OPAQUE, de ratchet en de VDF zijn nog niet gemeten." },
      { id: "pq-ratchet", level: "building", title: "Post-kwantum ratchet (ML-KEM-1024 + X25519)", body: "Gebouwd en getest in de rekenmodule en de crypto-worker, met ondertekende sleutelbundels per lid.", open: "Nog geen berichtenschermen en geen live test met een hardware-passkey." },
      { id: "vdf", level: "building", title: "Wesolowski VDF", body: "Alleen class groups van imaginaire kwadratische lichamen (D ≡ 1 mod 4), zonder vertrouwde opzet, met NUCOMP/NUDUPL. De RSA-2048-variant is verwijderd. Getest, maar nog nergens in de app gebruikt." },
      { id: "hardware-binding", level: "open", title: "Boekingssleutel aan een hardwaresleutel binden", body: "De boekingssleutel van de host is nu verzegeld met de hoofdsleutel, nog niet met een hardware-passkey." },
    ],
  },
  en: {
    heading: "Status: bookings and cryptography",
    intro: "Per part, what is in the code and tested, and what is still open. A passing test is not a guarantee, and none of this is an external audit.",
    levels: { tested: "In the code, tested", building: "Building block, not in use yet", open: "Still open" },
    openLabel: "Still open",
    items: [
      { id: "sealed-bookings", level: "tested", title: "Encrypted guest details when booking", body: "Name, email, note and answers are encrypted in the guest's browser for the host's booking key (ML-KEM-1024 + X25519). The server only stores encrypted text and refuses unencrypted guest details. The same applies to the short request form on profile cards. The host opens them only on their own device.", open: "A live booking or request on the site, and a copy for the guest." },
      { id: "server-guards", level: "tested", title: "Every server function checks who is asking", body: "Functions for signed-in members check the session on the server, not only in the browser. Intentionally public functions are on a fixed list. An automated test fails for every new function without a check." },
      { id: "formal-rls", level: "tested", title: "Mathematical proof of the database rules (Z3)", body: "At database level 0277, 1,170 of the 1,210 proof obligations are proven with the Z3 solver; 10 are intentionally declassified, 30 sit at the server boundary, 0 are unproven.", open: "55 known places where a unique key can reveal something; the sign-in system is outside this model." },
      { id: "dudect", level: "tested", title: "Timing measurement (dudect)", body: "1,000,000 measurements per operation for X25519, ML-KEM-1024, constant-time comparison, PRF to HKDF and AES-256-GCM: all below the threshold |t| < 4.5 (highest 4.08). This is statistical evidence, not a guarantee.", open: "OPAQUE, the ratchet and the VDF have not been measured yet." },
      { id: "pq-ratchet", level: "building", title: "Post-quantum ratchet (ML-KEM-1024 + X25519)", body: "Built and tested in the compute module and the crypto worker, with signed key bundles per member.", open: "No messaging screens yet and no live test with a hardware passkey." },
      { id: "vdf", level: "building", title: "Wesolowski VDF", body: "Only class groups of imaginary quadratic fields (D ≡ 1 mod 4), without a trusted setup, using NUCOMP/NUDUPL. The RSA-2048 variant has been removed. Tested, but not used anywhere in the app yet." },
      { id: "hardware-binding", level: "open", title: "Binding the booking key to a hardware key", body: "The host's booking key is currently sealed with the master key, not yet with a hardware passkey." },
    ],
  },
  fr: {
    heading: "État des lieux : réservations et cryptographie",
    intro: "Pour chaque élément, ce qui est dans le code et testé, et ce qui reste ouvert. Un test réussi n'est pas une garantie, et rien de ceci n'est un audit externe.",
    levels: { tested: "Dans le code, testé", building: "Brique de base, pas encore utilisée", open: "Encore ouvert" },
    openLabel: "Encore ouvert",
    items: [
      { id: "sealed-bookings", level: "tested", title: "Données d'invité chiffrées lors de la réservation", body: "Le nom, l'e-mail, la note et les réponses sont chiffrés dans le navigateur de l'invité pour la clé de réservation de l'hôte (ML-KEM-1024 + X25519). Le serveur ne conserve que du texte chiffré et refuse les données d'invité non chiffrées. Il en va de même pour le court formulaire de demande sur les cartes de profil. L'hôte ne les ouvre que sur son propre appareil.", open: "Une réservation ou une demande réelle sur le site, et une copie pour l'invité." },
      { id: "server-guards", level: "tested", title: "Chaque fonction serveur vérifie qui demande", body: "Les fonctions pour les membres connectés vérifient la session sur le serveur, pas seulement dans le navigateur. Les fonctions volontairement publiques figurent sur une liste fixe. Un test automatique échoue pour toute nouvelle fonction sans vérification." },
      { id: "formal-rls", level: "tested", title: "Preuve mathématique des règles de la base de données (Z3)", body: "Au niveau de base de données 0277, 1 170 des 1 210 obligations de preuve sont prouvées avec le solveur Z3 ; 10 sont volontairement déclassifiées, 30 se situent à la frontière du serveur, 0 ne sont pas prouvées.", open: "55 endroits connus où une clé unique peut révéler quelque chose ; le système de connexion est en dehors de ce modèle." },
      { id: "dudect", level: "tested", title: "Mesure de temps (dudect)", body: "1 000 000 de mesures par opération pour X25519, ML-KEM-1024, la comparaison à temps constant, PRF vers HKDF et AES-256-GCM : toutes sous le seuil |t| < 4,5 (maximum 4,08). C'est une preuve statistique, pas une garantie.", open: "OPAQUE, le ratchet et la VDF n'ont pas encore été mesurés." },
      { id: "pq-ratchet", level: "building", title: "Ratchet post-quantique (ML-KEM-1024 + X25519)", body: "Construit et testé dans le module de calcul et le worker cryptographique, avec des paquets de clés signés par membre.", open: "Pas encore d'écrans de messagerie ni de test réel avec une passkey matérielle." },
      { id: "vdf", level: "building", title: "VDF de Wesolowski", body: "Uniquement les groupes de classes de corps quadratiques imaginaires (D ≡ 1 mod 4), sans configuration de confiance, avec NUCOMP/NUDUPL. La variante RSA-2048 a été supprimée. Testé, mais pas encore utilisé dans l'application." },
      { id: "hardware-binding", level: "open", title: "Lier la clé de réservation à une clé matérielle", body: "La clé de réservation de l'hôte est actuellement scellée avec la clé principale, pas encore avec une passkey matérielle." },
    ],
  },
  de: {
    heading: "Stand der Dinge: Buchungen und Kryptografie",
    intro: "Pro Bereich, was im Code steht und getestet ist, und was noch offen ist. Ein bestandener Test ist keine Garantie, und nichts davon ist ein externes Audit.",
    levels: { tested: "Im Code, getestet", building: "Baustein, noch nicht im Einsatz", open: "Noch offen" },
    openLabel: "Noch offen",
    items: [
      { id: "sealed-bookings", level: "tested", title: "Verschlüsselte Gastdaten beim Buchen", body: "Name, E-Mail, Notiz und Antworten werden im Browser des Gastes für den Buchungsschlüssel des Gastgebers verschlüsselt (ML-KEM-1024 + X25519). Der Server speichert nur verschlüsselten Text und lehnt unverschlüsselte Gastdaten ab. Das gilt auch für das kurze Anfrageformular auf Profilkarten. Der Gastgeber öffnet sie nur auf seinem eigenen Gerät.", open: "Eine echte Buchung oder Anfrage auf der Website und eine Kopie für den Gast." },
      { id: "server-guards", level: "tested", title: "Jede Serverfunktion prüft, wer fragt", body: "Funktionen für angemeldete Mitglieder prüfen die Sitzung auf dem Server, nicht nur im Browser. Bewusst öffentliche Funktionen stehen auf einer festen Liste. Ein automatischer Test schlägt bei jeder neuen Funktion ohne Prüfung fehl." },
      { id: "formal-rls", level: "tested", title: "Mathematischer Nachweis der Datenbankregeln (Z3)", body: "Auf Datenbankstand 0277 sind 1.170 der 1.210 Beweisverpflichtungen mit dem Z3-Solver bewiesen; 10 sind bewusst freigegeben, 30 liegen an der Servergrenze, 0 sind unbewiesen.", open: "55 bekannte Stellen, an denen ein eindeutiger Schlüssel etwas verraten kann; das Anmeldesystem liegt außerhalb dieses Modells." },
      { id: "dudect", level: "tested", title: "Zeitmessung (dudect)", body: "1.000.000 Messungen pro Operation für X25519, ML-KEM-1024, Vergleich in konstanter Zeit, PRF zu HKDF und AES-256-GCM: alle unter der Schwelle |t| < 4,5 (höchster Wert 4,08). Das ist ein statistischer Nachweis, keine Garantie.", open: "OPAQUE, der Ratchet und die VDF sind noch nicht gemessen." },
      { id: "pq-ratchet", level: "building", title: "Post-Quanten-Ratchet (ML-KEM-1024 + X25519)", body: "Gebaut und getestet im Rechenmodul und im Krypto-Worker, mit signierten Schlüsselbündeln pro Mitglied.", open: "Noch keine Nachrichtenansichten und kein Live-Test mit einem Hardware-Passkey." },
      { id: "vdf", level: "building", title: "Wesolowski-VDF", body: "Nur Klassengruppen imaginär-quadratischer Zahlkörper (D ≡ 1 mod 4), ohne vertrauenswürdiges Setup, mit NUCOMP/NUDUPL. Die RSA-2048-Variante wurde entfernt. Getestet, aber noch nirgends in der App verwendet." },
      { id: "hardware-binding", level: "open", title: "Buchungsschlüssel an einen Hardwareschlüssel binden", body: "Der Buchungsschlüssel des Gastgebers ist derzeit mit dem Hauptschlüssel versiegelt, noch nicht mit einem Hardware-Passkey." },
    ],
  },
};

export function securityStatus(locale: string): StatusText {
  const l = locale.slice(0, 2) as Locale4;
  return TEXT[l] ?? TEXT.en;
}

export const SECURITY_STATUS_LOCALES = Object.keys(TEXT) as Locale4[];

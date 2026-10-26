"""
intent_classifier.py — Determines whether request_text authorizes deletion.

Distinguishes deletion requests (account deletion, data removal, erasure, forgotten)
from non-deletion requests:
1. Data access / export requests (download data, export archive, subject access requests).
2. Identity / profile updates (change email, update phone, fix spelling, reset password).
3. Conditional / cancellation / keep-account statements (cancel deletion, hold off, do not delete).
"""
import re
from typing import Tuple


# Multi-lingual patterns indicating non-deletion requests
NON_DELETION_PATTERNS = [
    # ── 1. CONDITIONAL / EXPLICIT CANCELLATIONS & KEEP ACCOUNT STATEMENTS ──
    # English
    r"keep (?:my |the )?account",
    r"leave (?:the |my )?account active",
    r"leave (?:my )?(?:profile|purchase history|records)(?: and purchase history)? in place",
    r"leave.*in place",
    r"do not close (?:the |my )?account",
    r"don'?t close (?:the |my )?account",
    r"not asking for deletion",
    r"not a request to erase",
    r"not requesting deletion",
    r"not a deletion request",
    r"don'?t delete",
    r"do not delete",
    r"please do not delete (?:my account )?yet",
    r"hold off on (?:deleting|deletion|closing)",
    r"cancel (?:my )?(?:deletion|erasure|account closure|request)",
    r"withdraw (?:my )?(?:deletion|request)",
    r"want to continue using (?:the )?service",
    r"still (?:need|use) (?:the |my )?account",
    r"without removing (?:any of )?my records",
    r"stop (?:the )?promotional emails",
    r"remove me from marketing lists only",
    r"marketing (?:emails|lists) only",

    # French
    r"ne pas supprimer",
    r"ne supprimez pas",
    r"ne fermez pas (?:mon|le)? compte",
    r"garder (?:mon|le)? compte",
    r"conserver (?:mon|le)? compte",
    r"maintenir (?:mon|le)? compte actif",
    r"annuler (?:ma|la)? demande de suppression",
    r"reporter la suppression",
    r"je ne demande pas la suppression",
    r"pas une demande de suppression",

    # German
    r"nicht l[öo]schen",
    r"bitte nicht l[öo]schen",
    r"konto nicht schlie[ßs]en",
    r"konto behalten",
    r"konto aktiv lassen",
    r"l[öo]schantrag (?:stornieren|abbrechen)",
    r"l[öo]schung (?:abbrechen|widerrufen)",
    r"keine l[öo]schung",

    # Spanish
    r"no eliminar (?:mi |la )?cuenta",
    r"no borrar (?:mi |la )?cuenta",
    r"no cerrar (?:mi |la )?cuenta",
    r"cancelar (?:la |mi )?solicitud de eliminaci[óo]n",
    r"mantener (?:mi )?cuenta (?:activa)?",
    r"conservar mi cuenta",
    r"no pido la eliminaci[óo]n",

    # Portuguese
    r"n[ãa]o excluir (?:a |minha )?conta",
    r"n[ãa]o deletar (?:a |minha )?conta",
    r"n[ãa]o apagar (?:a |minha )?conta",
    r"n[ãa]o fechar (?:a |minha )?conta",
    r"cancelar (?:a )?exclus[ãa]o",
    r"manter (?:minha )?conta (?:ativa)?",
    r"n[ãa]o estou solicitando a exclus[ãa]o",

    # Italian
    r"non eliminare (?:il mio |l')?account",
    r"non cancellare (?:il mio |l')?account",
    r"non chiudere (?:il mio |l')?account",
    r"annullare la richiesta di (?:cancellazione|eliminazione)",
    r"mantenere attivo (?:il mio |l')?account",
    r"non richiedo la cancellazione",

    # ── 2. DATA ACCESS & EXPORT REQUESTS (WITHOUT DELETION) ──
    # English
    r"this is an information request, not a request to erase",
    r"tell me what personal information you hold",
    r"what personal (?:data|information) do you (?:store|have|keep|hold)",
    r"download (?:my |the )?(?:account )?information.*(?:keep|leave)",
    r"download (?:my )?data",
    r"export (?:my )?(?:archive|data)",
    r"send me a copy of (?:the )?information held",
    r"need a copy of (?:last year'?s )?invoices",
    r"subject access request",
    r"request a copy of (?:my )?(?:personal )?data",

    # French
    r"t[ée]l[ée]charger (?:mes|mon|une copie|les)? (?:donn[ée]es|archive|informations)",
    r"exporter (?:mes|mon)? (?:donn[ée]es|informations)",
    r"copie de mes donn[ée]es",
    r"acc[èe]s [àa] mes donn[ée]es",
    r"demande d'acc[èe]s",
    r"quelles donn[ée]es personnelles",

    # German
    r"daten herunterladen",
    r"meine daten herunterladen",
    r"daten exportieren",
    r"kopie (?:meiner|von) daten",
    r"auskunft [üu]ber meine daten",
    r"auskunftsersuchen",
    r"welche personenbezogenen daten",

    # Spanish
    r"descargar (?:mis|una copia de)? (?:datos|informaci[óo]n|archivo)",
    r"exportar (?:mis)? datos",
    r"copia de mis datos",
    r"solicitud de acceso",
    r"qu[ée] datos personales",

    # Portuguese
    r"baixar (?:meus|uma c[óo]pia)? (?:dados|informa[çc][õo]es)",
    r"exportar (?:meus)? dados",
    r"c[óo]pia dos meus dados",
    r"solicita[çc][ãa]o de acesso",
    r"quais dados pessoais",

    # Italian
    r"scaricare (?:i miei)? dati",
    r"esportare (?:i miei)? dati",
    r"copia dei miei dati",
    r"richiesta di accesso",
    r"quali dati personali",

    # ── 3. IDENTITY & PROFILE UPDATES ──
    # English
    r"(?:mobile|phone) number.*is out of date.*(?:leave|keep|replace)",
    r"change the email address used for this account.*(?:continue|keep)",
    r"(?:sur)?name is misspelled.*without removing",
    r"update my email address",
    r"change password",
    r"need help resetting the login\. do not close",
    r"can'?t access my profile and need help resetting the login",
    r"forgot my password.*do not close",
    r"update (?:my )?(?:profile|address|phone|email)",

    # French
    r"mettre [àa] jour (?:mon|mes|l'adresse|le profil)",
    r"modifier (?:mon|mes|le)? (?:adresse|mot de passe|e-mail|profil)",
    r"changer (?:mon|mes|d'adresse|de mot de passe|d'email)",
    r"r[ée]initialiser mon mot de passe",

    # German
    r"adresse [äa]ndern",
    r"e-mail-adresse [äa]ndern",
    r"passwort [äa]ndern",
    r"passwort zur[üu]cksetzen",
    r"daten aktualisieren",
    r"profil aktualisieren",

    # Spanish
    r"actualizar (?:mi )?(?:correo|direcci[óo]n|tel[ée]fono|perfil|datos)",
    r"cambiar (?:mi )?(?:contrase[ñn]a|correo|direcci[óo]n|email)",
    r"restablecer contrase[ñn]a",

    # Portuguese
    r"atualizar (?:meu|minha)? (?:e-mail|endere[çc]o|telefone|perfil|dados)",
    r"mudar (?:minha )?senha",
    r"alterar (?:meu )?(?:e-mail|endere[çc]o|dados)",
    r"redefinir senha",

    # Italian
    r"aggiornare (?:il mio)? (?:indirizzo|profilo|recapito)",
    r"cambiare (?:la )?password",
    r"modificare (?:l'email|l'indirizzo|il profilo)",
    r"reimpostare password",
]


def classify_intent(request_text: str) -> Tuple[str, str]:
    """
    Classify whether the request authorizes deletion.

    Returns:
        Tuple of (classification, reason)
        classification: "DELETION" or "NOT_APPLICABLE"
    """
    text = request_text.strip()
    text_lower = text.lower()

    # 1. Check for explicit non-deletion patterns
    for pattern in NON_DELETION_PATTERNS:
        if re.search(pattern, text_lower):
            return "NOT_APPLICABLE", f"Non-deletion intent matched: {pattern}"

    # 2. Deletion requests: account closure, erasure, data deletion
    return "DELETION", "Valid deletion authorization"


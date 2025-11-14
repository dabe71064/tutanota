// The patterns in this file capture variations of their kind, but are only approximations!
// DO NOT use them for validating dates, credit cards, etc.

import { Mail, MailAddress, MailDetails } from "../../../entities/tutanota/TypeRefs"
import { SpamMailDatum } from "./SpamMailProcessor"
import { getMailBodyText } from "../../CommonMailUtils"
import { assertNotNull } from "@tutao/tutanota-utils"
import { MailAuthenticationStatus } from "../../TutanotaConstants"

export const ML_DATE_REGEX = [
	/\b(?<!-)(?:\d{1,2}-){2}(?:\d\d|\d{4})(?!-)\b/g, // 01-12-2023 | 1-12-2023
	/\b(?<!\.)(?:\d{1,2}\.){2}(?:\d\d|\d{4})(?!\.)\b/g, // 01.12.2023 | 1.12.2023
	/\b(?:\d{1,2}\/){2}(?:\d\d|\d{4})\b/g, // 12/01/2023 | 12/1/2023 | 01/12/2023 | 1/12/2023
	/\b\d{4}(?:\/\d{1,2}){2}\b/g, // 2023/12/01 | 2023/12/1
	/\b(?<!-)\d{4}(?:-\d{1,2}){2}(?!-)\b/g, // 2023-12-01 | 2023-12-1
]

export const ML_DATE_TOKEN = " TDATE "

export const ML_URL_REGEX = /(?:http|https|ftp|sftp):\/\/([\w.-]+)(?:\/[^\s]*)?/g

export const ML_URL_TOKEN = " TURL$1 "

export const ML_EMAIL_ADDR_REGEX = /(?:mailto:)?[A-Za-z0-9_+\-.]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
export const ML_EMAIL_ADDR_TOKEN = " TEMAIL "

export const ML_BITCOIN_REGEX = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g

export const ML_BITCOIN_TOKEN = " TBITCOIN "

export const ML_CREDIT_CARD_REGEX = /\b(\d{4}\s?){4}\b|\b[0-9]\d{13,16}\b/g

export const ML_CREDIT_CARD_TOKEN = " TCREDITCARD "

export const ML_NUMBER_SEQUENCE_REGEX = /\b\d+\b/g

export const ML_NUMBER_SEQUENCE_TOKEN = " TNUMBER "

export const ML_SPECIAL_CHARACTER_REGEX = /([!@#$%^&*()[\]<>+`_=\\{}"':;?/,-.~]+)/g

export const ML_SPECIAL_CHARACTER_TOKEN = " TSPECIALCHAR "

export const ML_SPACE_BEFORE_NEW_LINE_REGEX = /\s+\n/g

export const ML_SPACE_BEFORE_NEW_LINE_TOKEN = "\n"
export function createSpamMailDatum(mail: Mail, mailDetails: MailDetails) {
	const spamMailDatum: SpamMailDatum = {
		subject: mail.subject,
		body: getMailBodyText(mailDetails.body),
		ownerGroup: assertNotNull(mail._ownerGroup),
		...extractSpamHeaderFeatures(mail, mailDetails),
	}
	return spamMailDatum
}

export function extractSpamHeaderFeatures(mail: Mail, mailDetails: MailDetails) {
	const sender = joinNamesAndMailAddresses([mail?.sender])
	const { toRecipients, ccRecipients, bccRecipients } = extractRecipients(mailDetails)
	const authStatus = convertAuthStatusToSpamCategorizationToken(mail.authStatus)

	return { sender, toRecipients, ccRecipients, bccRecipients, authStatus }
}

function extractRecipients({ recipients }: MailDetails) {
	const toRecipients = joinNamesAndMailAddresses(recipients?.toRecipients)
	const ccRecipients = joinNamesAndMailAddresses(recipients?.ccRecipients)
	const bccRecipients = joinNamesAndMailAddresses(recipients?.bccRecipients)

	return { toRecipients, ccRecipients, bccRecipients }
}

function joinNamesAndMailAddresses(recipients: MailAddress[] | null) {
	return recipients?.map((recipient) => `${recipient?.name} ${recipient?.address}`).join(" ") || ""
}

function convertAuthStatusToSpamCategorizationToken(authStatus: string | null): string {
	if (authStatus === MailAuthenticationStatus.AUTHENTICATED) {
		return "TAUTHENTICATED"
	} else if (authStatus === MailAuthenticationStatus.HARD_FAIL) {
		return "THARDFAIL"
	} else if (authStatus === MailAuthenticationStatus.SOFT_FAIL) {
		return "TSOFTFAIL"
	} else if (authStatus === MailAuthenticationStatus.INVALID_MAIL_FROM) {
		return "TINVALIDMAILFROM"
	} else if (authStatus === MailAuthenticationStatus.MISSING_MAIL_FROM) {
		return "TMISSINGMAILFROM"
	}

	return ""
}

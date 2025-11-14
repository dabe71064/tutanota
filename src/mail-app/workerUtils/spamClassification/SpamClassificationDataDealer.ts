import { EntityClient } from "../../../common/api/common/EntityClient"
import { assertNotNull, isEmpty, isNotNull, last, lazyAsync, promiseMap } from "@tutao/tutanota-utils"
import {
	ClientSpamTrainingDatum,
	ClientSpamTrainingDatumIndexEntryTypeRef,
	ClientSpamTrainingDatumTypeRef,
	MailBag,
	MailBox,
	MailboxGroupRootTypeRef,
	MailBoxTypeRef,
	MailFolder,
	MailFolderTypeRef,
	MailTypeRef,
	PopulateClientSpamTrainingDatum,
} from "../../../common/api/entities/tutanota/TypeRefs"
import { DEFAULT_IS_SPAM_CONFIDENCE, getMailSetKind, isFolder, MailSetKind, SpamDecision } from "../../../common/api/common/TutanotaConstants"
import { GENERATED_MIN_ID, getElementId, isSameId, StrippedEntity, timestampToGeneratedId } from "../../../common/api/common/utils/EntityUtils"
import { BulkMailLoader, MailWithMailDetails } from "../index/BulkMailLoader"
import { hasError } from "../../../common/api/common/utils/ErrorUtils"
import { SpamMailProcessor } from "../../../common/api/common/mail/spamClassificationUtils/SpamMailProcessor"
import { CacheMode } from "../../../common/api/worker/rest/EntityRestClient"
import { MailFacade } from "../../../common/api/worker/facades/lazy/MailFacade"

import { createSpamMailDatum } from "../../../common/api/common/mail/spamClassificationUtils/PreprocessPatterns"

/*
 * While downloading mails, we start from the current mailbag. However, it might be that the current mailbag is too new,
 * If there is less than this number of mails in the current mailbag, we will also try to fetch the previous one
 */
const MIN_MAILBAG_MAILS_COUNT: number = 300

const SINGLE_TRAIN_INTERVAL_TRAINING_DATA_LIMIT = 1000
const INITIAL_SPAM_CLASSIFICATION_INDEX_INTERVAL_DAYS = 90
const TRAINING_DATA_TIME_LIMIT: number = INITIAL_SPAM_CLASSIFICATION_INDEX_INTERVAL_DAYS * -1

export type TrainingDataset = {
	trainingData: ClientSpamTrainingDatum[]
	lastTrainingDataIndexId: Id
	hamCount: number
	spamCount: number
}

export type UnencryptedPopulateClientSpamTrainingDatum = Omit<StrippedEntity<PopulateClientSpamTrainingDatum>, "encVector" | "ownerEncVectorSessionKey"> & {
	vector: Uint8Array
}

export class SpamClassificationDataDealer {
	constructor(
		private readonly entityClient: EntityClient,
		private readonly bulkMailLoader: lazyAsync<BulkMailLoader>,
		private readonly mailFacade: lazyAsync<MailFacade>,
		private readonly spamMailProcessor: SpamMailProcessor = new SpamMailProcessor(),
	) {}

	public async fetchAllTrainingData(ownerGroup: Id): Promise<TrainingDataset> {
		const mailboxGroupRoot = await this.entityClient.load(MailboxGroupRootTypeRef, ownerGroup)
		const mailbox = await this.entityClient.load(MailBoxTypeRef, mailboxGroupRoot.mailbox)
		const mailSets = await this.entityClient.loadAll(MailFolderTypeRef, assertNotNull(mailbox.folders).folders)

		if (mailbox.clientSpamTrainingData == null || mailbox.modifiedClientSpamTrainingDataIndex == null) {
			return { trainingData: [], lastTrainingDataIndexId: GENERATED_MIN_ID, hamCount: 0, spamCount: 0 }
		}

		// clientSpamTrainingData is NOT cached
		let clientSpamTrainingData = await this.entityClient.loadAll(ClientSpamTrainingDatumTypeRef, mailbox.clientSpamTrainingData)

		// if the training data is empty for this mailbox, we are aggregating
		// the last INITIAL_SPAM_CLASSIFICATION_INDEX_INTERVAL_DAYS of mails and uploading the training data
		if (isEmpty(clientSpamTrainingData)) {
			console.log("building and uploading initial training data for mailbox: " + mailbox._id)
			const mailsWithMailDetails = await this.fetchMailAndMailDetailsForMailbox(mailbox, mailSets)
			console.log(`mailbox has ${mailsWithMailDetails.length} mails suitable for encrypted training vector data upload`)
			console.log(`vectorizing, compressing and encrypting those ${mailsWithMailDetails.length} mails...`)
			await this.uploadTrainingDataForMails(mailsWithMailDetails, mailbox, mailSets)
			clientSpamTrainingData = await this.entityClient.loadAll(ClientSpamTrainingDatumTypeRef, mailbox.clientSpamTrainingData)
			console.log(`clientSpamTrainingData list on the mailbox has ${clientSpamTrainingData.length} members.`)
		}
		clientSpamTrainingData.filter((datum) => Number(datum.confidence) > 0 && datum.spamDecision !== SpamDecision.NONE)
		const { subsampledTrainingData, hamCount, spamCount } = this.subsampleHamAndSpamMails(clientSpamTrainingData)

		const modifiedClientSpamTrainingDataIndices = await this.entityClient.loadAll(
			ClientSpamTrainingDatumIndexEntryTypeRef,
			mailbox.modifiedClientSpamTrainingDataIndex,
		)
		const lastModifiedClientSpamTrainingDataIndexElementId = isEmpty(modifiedClientSpamTrainingDataIndices)
			? GENERATED_MIN_ID
			: getElementId(assertNotNull(last(modifiedClientSpamTrainingDataIndices)))

		return {
			trainingData: subsampledTrainingData,
			lastTrainingDataIndexId: lastModifiedClientSpamTrainingDataIndexElementId,
			hamCount,
			spamCount,
		}
	}

	async fetchPartialTrainingDataFromIndexStartId(indexStartId: Id, ownerGroup: Id): Promise<TrainingDataset> {
		const mailboxGroupRoot = await this.entityClient.load(MailboxGroupRootTypeRef, ownerGroup)
		const mailbox = await this.entityClient.load(MailBoxTypeRef, mailboxGroupRoot.mailbox)

		const emptyResult = { trainingData: [], lastTrainingDataIndexId: indexStartId, hamCount: 0, spamCount: 0 }
		if (mailbox.clientSpamTrainingData == null || mailbox.modifiedClientSpamTrainingDataIndex == null) {
			return emptyResult
		}

		const modifiedClientSpamTrainingDataIndicesSinceStart = await this.entityClient.loadRange(
			ClientSpamTrainingDatumIndexEntryTypeRef,
			mailbox.modifiedClientSpamTrainingDataIndex,
			indexStartId,
			SINGLE_TRAIN_INTERVAL_TRAINING_DATA_LIMIT,
			false,
		)

		if (isEmpty(modifiedClientSpamTrainingDataIndicesSinceStart)) {
			return emptyResult
		}

		const clientSpamTrainingData = await this.entityClient.loadMultiple(
			ClientSpamTrainingDatumTypeRef,
			mailbox.clientSpamTrainingData,
			modifiedClientSpamTrainingDataIndicesSinceStart.map((index) => index.clientSpamTrainingDatumElementId),
			undefined,
			{ cacheMode: CacheMode.WriteOnly }, // needs to be writeOnly to ensure that the cacheStorage is updated
		)

		clientSpamTrainingData.filter(
			(datum) => Number(datum.confidence) > 0 && datum.spamDecision !== SpamDecision.NONE && datum.spamDecision !== SpamDecision.DISCARD,
		)
		const { subsampledTrainingData, hamCount, spamCount } = this.subsampleHamAndSpamMails(clientSpamTrainingData)

		return {
			trainingData: subsampledTrainingData,
			lastTrainingDataIndexId: getElementId(assertNotNull(last(modifiedClientSpamTrainingDataIndicesSinceStart))),
			hamCount,
			spamCount,
		}
	}

	private async fetchMailAndMailDetailsForMailbox(mailbox: MailBox, mailSets: MailFolder[]): Promise<Array<MailWithMailDetails>> {
		const downloadedMailClassificationData = new Array<MailWithMailDetails>()

		const { LocalTimeDateProvider } = await import("../../../common/api/worker/DateProvider.js")
		const dateProvider = new LocalTimeDateProvider()
		const startDate = dateProvider.getStartOfDayShiftedBy(TRAINING_DATA_TIME_LIMIT)

		// sorted from latest to oldest
		const mailbagsToFetch = [assertNotNull(mailbox.currentMailBag), ...mailbox.archivedMailBags.reverse()]
		for (let currentMailbag = mailbagsToFetch.shift(); isNotNull(currentMailbag); currentMailbag = mailbagsToFetch.shift()) {
			const mailsOfThisMailbag = await this.fetchMailsByMailbagAfterDate(currentMailbag, mailSets, startDate)
			if (isEmpty(mailsOfThisMailbag)) {
				// the list is empty if none of the mails in the mailbag were recent enough,
				// therefore, there is no point in requesting the remaining mailbags unnecessarily
				break
			}
			downloadedMailClassificationData.push(...mailsOfThisMailbag)
		}
		return downloadedMailClassificationData
	}

	private async fetchMailsByMailbagAfterDate(mailbag: MailBag, mailSets: MailFolder[], startDate: Date): Promise<Array<MailWithMailDetails>> {
		const bulkMailLoader = await this.bulkMailLoader()
		return await this.entityClient
			.loadAll(MailTypeRef, mailbag.mails, timestampToGeneratedId(startDate.getTime()))
			// Filter out draft mails, mails with error, mails older than INITIAL_SPAM_CLASSIFICATION_INDEX_INTERVAL_DAYS days, and mails in the trash folder.
			.then((mails) => {
				return mails.filter((mail) => {
					const trashFolder = assertNotNull(mailSets.find((set) => getMailSetKind(set) === MailSetKind.TRASH))
					const isMailTrashed = mail.sets.some((setId) => isSameId(setId, trashFolder._id))
					return isNotNull(mail.mailDetails) && !hasError(mail) && mail.receivedDate > startDate && !isMailTrashed
				})
			})
			// Download mail details
			.then((mails) => bulkMailLoader.loadMailDetails(mails))
	}

	private async uploadTrainingDataForMails(mails: MailWithMailDetails[], mailBox: MailBox, mailSets: MailFolder[]): Promise<void> {
		const clientSpamTrainingDataListId = mailBox.clientSpamTrainingData
		if (clientSpamTrainingDataListId == null) {
			return
		}

		const unencryptedPopulateClientSpamTrainingData: UnencryptedPopulateClientSpamTrainingDatum[] = await promiseMap(
			mails,
			async (mailWithDetail) => {
				const { mail, mailDetails } = mailWithDetail
				const allMailFolders = mailSets.filter((mailSet) => isFolder(mailSet)).map((mailFolder) => mailFolder._id)
				const sourceMailFolderId = assertNotNull(mail.sets.find((setId) => allMailFolders.find((folderId) => isSameId(setId, folderId))))
				const sourceMailFolder = assertNotNull(mailSets.find((set) => isSameId(set._id, sourceMailFolderId)))
				const isSpam = getMailSetKind(sourceMailFolder) === MailSetKind.SPAM
				const unencryptedPopulateClientSpamTrainingData: UnencryptedPopulateClientSpamTrainingDatum = {
					mailId: mail._id,
					isSpam,
					confidence: DEFAULT_IS_SPAM_CONFIDENCE.toString(), // fixme do trash handling or filter trashed mails and send default for all remaining mails
					vector: await this.spamMailProcessor.vectorizeAndCompress(createSpamMailDatum(mail, mailDetails)),
				}
				return unencryptedPopulateClientSpamTrainingData
			},
			{
				concurrency: 5,
			},
		)
		// we are uploading the initial spam training data using the ProcessInboxService
		return (await this.mailFacade()).populateClientSpamTrainingData(assertNotNull(mailBox._ownerGroup), unencryptedPopulateClientSpamTrainingData)
	}

	// Visible for testing
	subsampleHamAndSpamMails(clientSpamTrainingData: ClientSpamTrainingDatum[]): {
		subsampledTrainingData: ClientSpamTrainingDatum[]
		hamCount: number
		spamCount: number
	} {
		const hamData = clientSpamTrainingData.filter((d) => d.spamDecision === SpamDecision.WHITELIST)
		const spamData = clientSpamTrainingData.filter((d) => d.spamDecision === SpamDecision.BLACKLIST || d.spamDecision === SpamDecision.DISCARD)

		const hamCount = hamData.length
		const spamCount = spamData.length

		if (hamCount === 0 || spamCount === 0) {
			return { subsampledTrainingData: clientSpamTrainingData, hamCount, spamCount }
		}

		const ratio = hamCount / spamCount
		const MAX_RATIO = 10
		const MIN_RATIO = 1 / 10

		let finalHam = hamData
		let finalSpam = spamData

		if (ratio > MAX_RATIO) {
			const targetHamCount = Math.floor(spamCount * MAX_RATIO)
			finalHam = this.sampleEntriesFromArray(hamData, targetHamCount)
		} else if (ratio < MIN_RATIO) {
			const targetSpamCount = Math.floor(hamCount * MAX_RATIO)
			finalSpam = this.sampleEntriesFromArray(spamData, targetSpamCount)
		}

		const balanced = [...finalHam, ...finalSpam]
		console.log(
			`Subsampled training data to ${finalHam.length} ham and ${finalSpam.length} spam (ratio ${(finalHam.length / finalSpam.length).toFixed(2)}).`,
		)

		return { subsampledTrainingData: balanced, hamCount: finalHam.length, spamCount: finalSpam.length }
	}

	private sampleEntriesFromArray<T>(arr: T[], numberOfEntries: number): T[] {
		if (numberOfEntries >= arr.length) {
			return arr
		}
		const shuffled = arr.slice().sort(() => Math.random() - 0.5)
		return shuffled.slice(0, numberOfEntries)
	}
}

import { PdfDocument } from "../pdf/PdfDocument.js"
import { PdfWriter } from "../pdf/PdfWriter.js"

export class PdfRecoveryDocumentGenerator {
	private readonly doc: PdfDocument
	private readonly recoveryCode: string

	constructor(pdfWriter: PdfWriter, recoveryCode: string) {
		this.recoveryCode = recoveryCode
		this.doc = new PdfDocument(pdfWriter)
	}

	/**
	 * Generate the PDF document
	 */
	async generate(): Promise<Uint8Array> {
		await this.doc.addPage()
		this.doc.addAddressField([0, 0], "")
		this.doc.addText(this.recoveryCode, [10, 10])
		return await this.doc.create()
	}
}

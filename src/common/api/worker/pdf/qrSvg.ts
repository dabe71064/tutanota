export type FillColor = 0 | 1 // 0 = black, 1 = white

export interface QrRect {
	x: number
	y: number
	width: number
	height: number
	fill: FillColor
}

export interface ParsedQr {
	width: number
	height: number
	rects: QrRect[]
}

const EPS = 1e-6

/** Parse numeric attributes like "180" or "180px". */
function parseNumeric(value?: string): number {
	if (!value) return 0
	return parseFloat(value.replace(/px$/i, ""))
}

/** Extract attributes from a single tag string. */
function parseAttributes(tag: string): Record<string, string> {
	const attributes: Record<string, string> = {}
	const matcher = tag.matchAll(/([a-zA-Z_:][\w:.-]*)\s*=\s*"([^"]*)"/g)
	for (const [, key, val] of matcher) attributes[key] = val
	return attributes
}

/** Parse hex color (#000 / #000000) to FillColor or null if not pure bw. */
function hexToFillColor(hex: string): FillColor | null {
	const normalized =
		hex.length === 3
			? hex
					.split("")
					.map((c) => c + c)
					.join("")
			: hex
	const int = parseInt(normalized, 16)
	const r = (int >> 16) & 255
	const g = (int >> 8) & 255
	const b = int & 255
	if (r === 255 && g === 255 && b === 255) return 1
	if (r === 0 && g === 0 && b === 0) return 0
	return null
}

/** Get FillColor (0/1) from style="fill:..."*/
function parseFillColor(styleAttr?: string): FillColor | null {
	// 1) style="fill: ..."
	let styleFill: string | undefined
	if (styleAttr) {
		const styleMap: Record<string, string> = {}
		for (const part of styleAttr.split(";")) {
			const [k, v] = part.split(":")
			if (k && v) styleMap[k.trim().toLowerCase()] = v.trim().toLowerCase()
		}
		styleFill = styleMap["fill"]
	}

	const chosen = styleFill?.toLowerCase()

	if (!chosen) return null

	if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(chosen)) {
		const fillColor = hexToFillColor(chosen.slice(1))
		if (fillColor !== null) return fillColor
	}

	// Unknown color → treat as black for QR use cases.
	return 0
}

/** Parse a restricted QR-style SVG: <svg ...> + <rect ... style="fill:..."/>. */
export function parseQrSvg(svg: string): ParsedQr {
	const svgTag = svg.match(/<svg\b[^>]*>/i)?.[0]
	if (!svgTag) throw new Error("No <svg> tag found")

	const svgAttributes = parseAttributes(svgTag)
	const svgWidth = parseNumeric(svgAttributes["width"])
	const svgHeight = parseNumeric(svgAttributes["height"])
	if (!(svgWidth > 0 && svgHeight > 0)) {
		throw new Error(`Invalid SVG dimensions: ${svgWidth}x${svgHeight}`)
	}

	const rectangles: QrRect[] = []

	for (const match of svg.matchAll(/<rect\b[^>]*\/?>/gi)) {
		const rectTag = match[0]
		const a = parseAttributes(rectTag)

		const x = parseNumeric(a["x"])
		const y = parseNumeric(a["y"])
		const width = parseNumeric(a["width"])
		const height = parseNumeric(a["height"])
		if (!(width > 0 && height > 0)) continue

		const fillColor = parseFillColor(a["style"])

		const isBackgroundRect = fillColor === 1 && x < EPS && y < EPS && Math.abs(width - svgWidth) < EPS && Math.abs(height - svgHeight) < EPS

		if (isBackgroundRect) {
			continue
		}

		rectangles.push({ x, y, width: width, height: height, fill: (fillColor ?? 0) as FillColor })
	}

	return { width: svgWidth, height: svgHeight, rects: rectangles }
}

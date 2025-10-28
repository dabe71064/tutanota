export interface QrRect {
	x: number
	y: number
	width: number
	height: number
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
	// iterate over key="value" pairs inside a single tag string
	const matcher = tag.matchAll(/([a-zA-Z_:][\w:.-]*)\s*=\s*"([^"]*)"/g)
	for (const [, key, val] of matcher) attributes[key] = val
	return attributes
}

/** Parse a restricted QR-style SVG: <svg ...> + <rect ... style="fill:..."/>. */
export function parseQrSvg(svg: string): ParsedQr {
	// grab the first <svg ...> tag so we can read width/height
	const svgTag = svg.match(/<svg\b[^>]*>/i)?.[0]
	if (!svgTag) throw new Error("No <svg> tag found")

	const svgAttributes = parseAttributes(svgTag)
	const svgWidth = parseNumeric(svgAttributes["width"])
	const svgHeight = parseNumeric(svgAttributes["height"])
	if (!(svgWidth > 0 && svgHeight > 0)) {
		throw new Error(`Invalid SVG dimensions: ${svgWidth}x${svgHeight}`)
	}

	const rectangles: QrRect[] = []

	// iterate over every <rect ...> start tag. Matches both <rect ...> and self-closing <rect .../> tags
	for (const match of svg.matchAll(/<rect\b[^>]*\/?>/gi)) {
		const rectTag = match[0]
		const attrs = parseAttributes(rectTag)

		const x = parseNumeric(attrs["x"])
		const y = parseNumeric(attrs["y"])
		const width = parseNumeric(attrs["width"])
		const height = parseNumeric(attrs["height"])
		if (!(width > 0 && height > 0)) continue
		const isBackgroundRect = x < EPS && y < EPS && Math.abs(width - svgWidth) < EPS && Math.abs(height - svgHeight) < EPS
		if (!isBackgroundRect) rectangles.push({ x, y, width: width, height: height })
	}
	return { width: svgWidth, height: svgHeight, rects: rectangles }
}

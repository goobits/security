/** Browser markup sanitization based on explicit element, attribute, and CSS allowlists. */

const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml'
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg'

const allowedHtmlElements = new Set([
	'a',
	'abbr',
	'address',
	'article',
	'aside',
	'b',
	'bdi',
	'bdo',
	'blockquote',
	'br',
	'button',
	'caption',
	'cite',
	'code',
	'col',
	'colgroup',
	'data',
	'dd',
	'del',
	'details',
	'dfn',
	'div',
	'dl',
	'dt',
	'em',
	'fieldset',
	'figcaption',
	'figure',
	'footer',
	'form',
	'h1',
	'h2',
	'h3',
	'h4',
	'h5',
	'h6',
	'header',
	'hgroup',
	'hr',
	'i',
	'img',
	'input',
	'ins',
	'kbd',
	'label',
	'legend',
	'li',
	'main',
	'mark',
	'menu',
	'meter',
	'nav',
	'ol',
	'optgroup',
	'option',
	'output',
	'p',
	'picture',
	'pre',
	'progress',
	'q',
	'rp',
	'rt',
	'ruby',
	's',
	'samp',
	'search',
	'section',
	'select',
	'small',
	'span',
	'strong',
	'sub',
	'summary',
	'sup',
	'table',
	'tbody',
	'td',
	'textarea',
	'tfoot',
	'th',
	'thead',
	'time',
	'tr',
	'u',
	'ul',
	'var',
	'wbr'
])

const allowedHtmlAttributes = new Set([
	'abbr',
	'accept',
	'alt',
	'autocomplete',
	'checked',
	'cite',
	'class',
	'colspan',
	'controls',
	'coords',
	'datetime',
	'dir',
	'disabled',
	'for',
	'headers',
	'height',
	'hidden',
	'high',
	'href',
	'id',
	'lang',
	'loading',
	'loop',
	'low',
	'max',
	'maxlength',
	'media',
	'method',
	'min',
	'minlength',
	'multiple',
	'muted',
	'name',
	'open',
	'optimum',
	'pattern',
	'placeholder',
	'playsinline',
	'poster',
	'preload',
	'readonly',
	'rel',
	'required',
	'reversed',
	'role',
	'rowspan',
	'selected',
	'shape',
	'size',
	'span',
	'src',
	'start',
	'step',
	'style',
	'tabindex',
	'target',
	'title',
	'type',
	'value',
	'width',
	'wrap'
])

const allowedSvgElements = new Set([
	'circle',
	'clippath',
	'defs',
	'desc',
	'ellipse',
	'g',
	'line',
	'lineargradient',
	'mask',
	'path',
	'polygon',
	'polyline',
	'radialgradient',
	'rect',
	'stop',
	'svg',
	'title',
	'use'
])

const allowedSvgAttributes = new Set([
	'aria-hidden',
	'aria-label',
	'class',
	'clip-path',
	'clip-rule',
	'cx',
	'cy',
	'd',
	'fill',
	'fill-opacity',
	'fill-rule',
	'focusable',
	'gradienttransform',
	'gradientunits',
	'height',
	'href',
	'id',
	'mask',
	'offset',
	'opacity',
	'points',
	'r',
	'role',
	'rx',
	'ry',
	'stop-color',
	'stroke',
	'stroke-dasharray',
	'stroke-dashoffset',
	'stroke-linecap',
	'stroke-linejoin',
	'stroke-miterlimit',
	'stroke-opacity',
	'stroke-width',
	'transform',
	'viewbox',
	'width',
	'x',
	'x1',
	'x2',
	'xmlns',
	'y',
	'y1',
	'y2'
])

const allowedCssProperties = new Set([
	'align-content',
	'align-items',
	'align-self',
	'aspect-ratio',
	'background',
	'background-color',
	'background-image',
	'background-position',
	'background-repeat',
	'background-size',
	'border',
	'border-block',
	'border-block-color',
	'border-block-style',
	'border-block-width',
	'border-bottom',
	'border-bottom-color',
	'border-bottom-left-radius',
	'border-bottom-right-radius',
	'border-bottom-style',
	'border-bottom-width',
	'border-collapse',
	'border-color',
	'border-inline',
	'border-inline-color',
	'border-inline-style',
	'border-inline-width',
	'border-left',
	'border-left-color',
	'border-left-style',
	'border-left-width',
	'border-radius',
	'border-right',
	'border-right-color',
	'border-right-style',
	'border-right-width',
	'border-spacing',
	'border-style',
	'border-top',
	'border-top-color',
	'border-top-left-radius',
	'border-top-right-radius',
	'border-top-style',
	'border-top-width',
	'border-width',
	'bottom',
	'box-shadow',
	'box-sizing',
	'color',
	'column-gap',
	'cursor',
	'display',
	'flex',
	'flex-basis',
	'flex-direction',
	'flex-flow',
	'flex-grow',
	'flex-shrink',
	'flex-wrap',
	'float',
	'font',
	'font-family',
	'font-feature-settings',
	'font-kerning',
	'font-size',
	'font-stretch',
	'font-style',
	'font-variant',
	'font-weight',
	'gap',
	'grid',
	'grid-area',
	'grid-auto-columns',
	'grid-auto-flow',
	'grid-auto-rows',
	'grid-column',
	'grid-column-end',
	'grid-column-start',
	'grid-row',
	'grid-row-end',
	'grid-row-start',
	'grid-template',
	'grid-template-areas',
	'grid-template-columns',
	'grid-template-rows',
	'height',
	'inset',
	'inset-block',
	'inset-inline',
	'isolation',
	'justify-content',
	'justify-items',
	'justify-self',
	'left',
	'letter-spacing',
	'line-height',
	'list-style',
	'list-style-position',
	'list-style-type',
	'margin',
	'margin-block',
	'margin-bottom',
	'margin-inline',
	'margin-left',
	'margin-right',
	'margin-top',
	'max-height',
	'max-width',
	'min-height',
	'min-width',
	'object-fit',
	'object-position',
	'opacity',
	'order',
	'outline',
	'outline-color',
	'outline-offset',
	'outline-style',
	'outline-width',
	'overflow',
	'overflow-wrap',
	'overflow-x',
	'overflow-y',
	'padding',
	'padding-block',
	'padding-bottom',
	'padding-inline',
	'padding-left',
	'padding-right',
	'padding-top',
	'pointer-events',
	'position',
	'resize',
	'right',
	'row-gap',
	'table-layout',
	'text-align',
	'text-decoration',
	'text-decoration-color',
	'text-decoration-line',
	'text-decoration-style',
	'text-indent',
	'text-overflow',
	'text-shadow',
	'text-transform',
	'top',
	'transform',
	'transform-origin',
	'transition',
	'transition-delay',
	'transition-duration',
	'transition-property',
	'transition-timing-function',
	'user-select',
	'vertical-align',
	'visibility',
	'white-space',
	'width',
	'word-break',
	'word-spacing',
	'z-index'
])

const urlAttributes = new Set(['href', 'poster', 'src'])
const svgReferenceAttributes = new Set(['clip-path', 'fill', 'href', 'mask', 'stroke'])
const safeRasterDataUrlPattern = /^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/iu

function createDomParser(): DOMParser | null {
	return typeof DOMParser === 'undefined' ? null : new DOMParser()
}

function isSafeHtmlUrl(value: string, attributeName: string): boolean {
	const normalized = value.trim()
	if (!normalized || /[\u0000-\u001f\u007f]/u.test(normalized)) return false
	if (attributeName === 'src' && safeRasterDataUrlPattern.test(normalized)) return true
	if (normalized.startsWith('//')) return false
	if (
		normalized.startsWith('#') ||
		normalized.startsWith('/') ||
		normalized.startsWith('./') ||
		normalized.startsWith('../')
	) {
		return true
	}
	return !normalized.includes(':')
}

function isLocalSvgReference(value: string): boolean {
	const normalized = value.trim()
	if (normalized.startsWith('#')) return true
	if (!normalized.toLowerCase().startsWith('url(') || !normalized.endsWith(')')) return false
	return normalized.slice(4, -1).trim().startsWith('#')
}

function isSafeCssValue(value: string): boolean {
	const normalized = value.toLowerCase().replaceAll(/\s/gu, '')
	return (
		!normalized.includes('url(') &&
		!normalized.includes('expression(') &&
		!normalized.includes('javascript:') &&
		!normalized.includes('vbscript:') &&
		!normalized.includes('data:text/html')
	)
}

function sanitizeStyleDeclaration(style: CSSStyleDeclaration): string {
	const declarations: string[] = []
	for (let index = 0; index < style.length; index += 1) {
		const property = style.item(index).toLowerCase()
		if (!property || (!property.startsWith('--') && !allowedCssProperties.has(property))) continue
		const value = style.getPropertyValue(property).trim()
		if (!value || !isSafeCssValue(value)) continue
		const priority = style.getPropertyPriority(property)
		declarations.push(`${property}: ${value}${priority ? ` !${priority}` : ''}`)
	}
	return declarations.length ? `${declarations.join('; ')};` : ''
}

function sanitizeHtmlElement(element: Element): boolean {
	if (element.namespaceURI === SVG_NAMESPACE) return sanitizeSvgElement(element)
	if (element.namespaceURI !== HTML_NAMESPACE || !allowedHtmlElements.has(element.localName)) {
		return false
	}

	for (const attributeName of element.getAttributeNames()) {
		const normalizedName = attributeName.toLowerCase()
		const value = element.getAttribute(attributeName) ?? ''
		if (
			normalizedName.startsWith('on') ||
			(!allowedHtmlAttributes.has(normalizedName) &&
				!normalizedName.startsWith('aria-') &&
				!normalizedName.startsWith('data-')) ||
			(urlAttributes.has(normalizedName) && !isSafeHtmlUrl(value, normalizedName))
		) {
			element.removeAttribute(attributeName)
			continue
		}
		if (normalizedName === 'style') {
			const sanitized = sanitizeStyleDeclaration((element as HTMLElement).style)
			if (sanitized) element.setAttribute(attributeName, sanitized)
			else element.removeAttribute(attributeName)
		}
	}

	for (const child of Array.from(element.children)) {
		if (!sanitizeHtmlElement(child)) child.remove()
	}
	return true
}

function sanitizeSvgElement(element: Element): boolean {
	const tagName = element.localName.toLowerCase()
	if (!allowedSvgElements.has(tagName)) return false

	for (const attributeName of element.getAttributeNames()) {
		const normalizedName = attributeName.toLowerCase()
		const value = element.getAttribute(attributeName) ?? ''
		const referenceValue = value.toLowerCase().includes('url(') || normalizedName === 'href'
		if (
			normalizedName.startsWith('on') ||
			!allowedSvgAttributes.has(normalizedName) ||
			(svgReferenceAttributes.has(normalizedName) && referenceValue && !isLocalSvgReference(value))
		) {
			element.removeAttribute(attributeName)
		}
	}

	for (const child of Array.from(element.children)) {
		if (!sanitizeSvgElement(child)) child.remove()
	}
	return true
}

/** Sanitizes an HTML fragment. Returns an empty string when DOMParser is unavailable. */
export function sanitizeHtml(value: string): string {
	const parser = createDomParser()
	if (!parser || !value.trim()) return ''
	const document = parser.parseFromString(value, 'text/html')
	for (const child of Array.from(document.body.children)) {
		if (!sanitizeHtmlElement(child)) child.remove()
	}
	return document.body.innerHTML
}

/** Sanitizes one complete SVG document. Returns an empty string for malformed input. */
export function sanitizeSvg(value: string): string {
	const parser = createDomParser()
	if (!parser || !value.trim()) return ''
	const document = parser.parseFromString(value, 'image/svg+xml')
	const root = document.documentElement
	if (document.querySelector('parsererror') || root.localName.toLowerCase() !== 'svg') return ''
	return sanitizeSvgElement(root) ? root.outerHTML : ''
}

/** Sanitizes a CSS stylesheet to allowlisted style rules and declarations. */
export function sanitizeCss(value: string): string {
	const parser = createDomParser()
	if (!parser || !value.trim()) return ''
	const parsedDocument = parser.parseFromString(
		'<!doctype html><html><head></head><body></body></html>',
		'text/html'
	)
	const ownerDocument = globalThis.document ?? parsedDocument
	const styleElement = ownerDocument.createElement('style')
	styleElement.textContent = value
	ownerDocument.head.append(styleElement)
	const rules = styleElement.sheet?.cssRules
	if (!rules) {
		styleElement.remove()
		return ''
	}

	const sanitized: string[] = []
	for (const rule of Array.from(rules)) {
		if (!('selectorText' in rule) || !('style' in rule)) continue
		const selector = String(rule.selectorText).trim()
		const declaration = sanitizeStyleDeclaration(rule.style as CSSStyleDeclaration)
		if (!selector || !declaration) continue
		sanitized.push(`${selector} { ${declaration} }`)
	}
	styleElement.remove()
	return sanitized.join('\n').replace(/<\/style/giu, '<\\/style')
}

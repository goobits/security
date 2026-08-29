/** Browser markup sanitization based on explicit element, attribute, and CSS allowlists. */

import {
	HTML_NAMESPACE,
	SVG_NAMESPACE,
	allowedCssProperties,
	allowedHtmlAttributes,
	allowedHtmlElements,
	allowedSvgAttributes,
	allowedSvgElements,
	safeRasterDataUrlPattern,
	svgReferenceAttributes,
	urlAttributes
} from './_internal/markupAllowlists.js';
function createDomParser(): DOMParser | null {
	return typeof DOMParser === 'undefined' ? null : new DOMParser();
}

function isSafeHtmlUrl(value: string, attributeName: string): boolean {
	const normalized = value.trim();
	if (!normalized || /[\u0000-\u001f\u007f]/u.test(normalized)) return false;
	if (attributeName === 'src' && safeRasterDataUrlPattern.test(normalized)) return true;
	if (normalized.startsWith('//')) return false;
	if (
		normalized.startsWith('#') ||
		normalized.startsWith('/') ||
		normalized.startsWith('./') ||
		normalized.startsWith('../')
	) {
		return true;
	}
	return !normalized.includes(':');
}

function isLocalSvgReference(value: string): boolean {
	const normalized = value.trim();
	if (normalized.startsWith('#')) return true;
	if (!normalized.toLowerCase().startsWith('url(') || !normalized.endsWith(')')) return false;
	return normalized.slice(4, -1).trim().startsWith('#');
}

function isSafeCssValue(value: string): boolean {
	const normalized = value.toLowerCase().replaceAll(/\s/gu, '');
	return (
		!normalized.includes('url(') &&
		!normalized.includes('expression(') &&
		!normalized.includes('javascript:') &&
		!normalized.includes('vbscript:') &&
		!normalized.includes('data:text/html')
	);
}

function sanitizeStyleDeclaration(style: CSSStyleDeclaration): string {
	const declarations: string[] = [];
	for (let index = 0; index < style.length; index += 1) {
		const property = style.item(index).toLowerCase();
		if (!property || (!property.startsWith('--') && !allowedCssProperties.has(property))) continue;
		const value = style.getPropertyValue(property).trim();
		if (!value || !isSafeCssValue(value)) continue;
		const priority = style.getPropertyPriority(property);
		declarations.push(`${property}: ${value}${priority ? ` !${priority}` : ''}`);
	}
	return declarations.length ? `${declarations.join('; ')};` : '';
}

function sanitizeHtmlElement(element: Element): boolean {
	if (element.namespaceURI === SVG_NAMESPACE) return sanitizeSvgElement(element);
	if (element.namespaceURI !== HTML_NAMESPACE || !allowedHtmlElements.has(element.localName)) {
		return false;
	}

	for (const attributeName of element.getAttributeNames()) {
		const normalizedName = attributeName.toLowerCase();
		const value = element.getAttribute(attributeName) ?? '';
		if (
			normalizedName.startsWith('on') ||
			(!allowedHtmlAttributes.has(normalizedName) &&
				!normalizedName.startsWith('aria-') &&
				!normalizedName.startsWith('data-')) ||
			(urlAttributes.has(normalizedName) && !isSafeHtmlUrl(value, normalizedName))
		) {
			element.removeAttribute(attributeName);
			continue;
		}
		if (normalizedName === 'style') {
			const sanitized = sanitizeStyleDeclaration((element as HTMLElement).style);
			if (sanitized) element.setAttribute(attributeName, sanitized);
			else element.removeAttribute(attributeName);
		}
	}

	for (const child of Array.from(element.children)) {
		if (!sanitizeHtmlElement(child)) child.remove();
	}
	return true;
}

function sanitizeSvgElement(element: Element): boolean {
	const tagName = element.localName.toLowerCase();
	if (!allowedSvgElements.has(tagName)) return false;

	for (const attributeName of element.getAttributeNames()) {
		const normalizedName = attributeName.toLowerCase();
		const value = element.getAttribute(attributeName) ?? '';
		const referenceValue = value.toLowerCase().includes('url(') || normalizedName === 'href';
		if (
			normalizedName.startsWith('on') ||
			!allowedSvgAttributes.has(normalizedName) ||
			(svgReferenceAttributes.has(normalizedName) && referenceValue && !isLocalSvgReference(value))
		) {
			element.removeAttribute(attributeName);
		}
	}

	for (const child of Array.from(element.children)) {
		if (!sanitizeSvgElement(child)) child.remove();
	}
	return true;
}

/** Sanitizes an HTML fragment. Returns an empty string when DOMParser is unavailable. */
export function sanitizeHtml(value: string): string {
	const parser = createDomParser();
	if (!parser || !value.trim()) return '';
	const document = parser.parseFromString(value, 'text/html');
	for (const child of Array.from(document.body.children)) {
		if (!sanitizeHtmlElement(child)) child.remove();
	}
	return document.body.innerHTML;
}

/** Sanitizes one complete SVG document. Returns an empty string for malformed input. */
export function sanitizeSvg(value: string): string {
	const parser = createDomParser();
	if (!parser || !value.trim()) return '';
	const document = parser.parseFromString(value, 'image/svg+xml');
	const root = document.documentElement;
	if (document.querySelector('parsererror') || root.localName.toLowerCase() !== 'svg') return '';
	return sanitizeSvgElement(root) ? root.outerHTML : '';
}

/** Sanitizes a CSS stylesheet to allowlisted style rules and declarations. */
export function sanitizeCss(value: string): string {
	const parser = createDomParser();
	if (!parser || !value.trim()) return '';
	const parsedDocument = parser.parseFromString(
		'<!doctype html><html><head></head><body></body></html>',
		'text/html'
	);
	const ownerDocument = globalThis.document ?? parsedDocument;
	const styleElement = ownerDocument.createElement('style');
	styleElement.textContent = value;
	ownerDocument.head.append(styleElement);
	const rules = styleElement.sheet?.cssRules;
	if (!rules) {
		styleElement.remove();
		return '';
	}

	const sanitized: string[] = [];
	for (const rule of Array.from(rules)) {
		if (!('selectorText' in rule) || !('style' in rule)) continue;
		const selector = String(rule.selectorText).trim();
		const declaration = sanitizeStyleDeclaration(rule.style as CSSStyleDeclaration);
		if (!selector || !declaration) continue;
		sanitized.push(`${selector} { ${declaration} }`);
	}
	styleElement.remove();
	return sanitized.join('\n').replace(/<\/style/giu, '<\\/style');
}

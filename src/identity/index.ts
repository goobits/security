export {
	buildDidWba,
	didWbaDomain,
	didWbaSignatureMessage,
	didWbaToUrl,
	parseDidWbaAuthorizationHeader,
	verifyDidWbaIdentity,
	type DidWbaAuthHeader,
	type DidWbaSignatureInput,
	type DidWbaVerificationError,
	type DidWbaVerificationResult,
	type DidWbaVerifyOptions
} from './did-wba.js'
export {
	parseHttpSignatureHeader,
	verifyHttpSignatureIdentity,
	type HttpSignatureHeader,
	type HttpSignatureVerificationError,
	type HttpSignatureVerificationInput,
	type HttpSignatureVerificationResult,
	type VerifyHttpSignatureOptions
} from './http-signature.js'
export {
	principalFromDid,
	principalFromHttpSignature,
	type IdentityMethod,
	type VerifiedPrincipal
} from './principal.js'

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
} from './didWba.js'
export {
	parseHttpSignatureHeader,
	verifyHttpSignatureIdentity,
	type HttpSignatureHeader,
	type HttpSignatureVerificationError,
	type HttpSignatureVerificationInput,
	type HttpSignatureVerificationResult,
	type VerifyHttpSignatureOptions
} from './httpSignature.js'
export {
	principalFromDid,
	principalFromHttpSignature,
	type IdentityMethod,
	type PrincipalIdentity,
	type VerifiedPrincipal
} from './principal.js'

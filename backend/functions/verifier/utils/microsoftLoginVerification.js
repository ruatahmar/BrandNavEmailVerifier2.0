const UserAgent = require('user-agents');
const { axiosGet, axiosPost } = require('../../utils/axios');
const winston = require('winston');
const { loggerTypes } = require('../../logging/logger');

const userAgent = new UserAgent({ platform: 'Win32' });
const logger = winston.loggers.get(loggerTypes.msLogin);

const LOGIN_PAGE_URL = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&response_mode=form_post&nonce=123456&ui_locales=en-US&mkt=en-US`;
const CREDENTIAL_URL = `https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US`;


/**
 * Fetches fresh tokens from Microsoft login page
 * @returns {Promise<{flowToken: string, sCtx: string, canary: string, cookies: string} | null>}
 */
async function getFreshTokens() {
	try {
		const response = await axiosGet(LOGIN_PAGE_URL, {
			headers: {
				'User-Agent': userAgent.toString(),
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'Accept-Language': 'en-US,en;q=0.9',
			},
			// get raw html back not json
			responseType: 'text',
			timeout: 10000,
		});

		if (!response.success || !response.data) {
			logger.error('Failed to fetch Microsoft login page');
			return null;
		}

		const html = response.data;

		// scrape tokens from the page html
		const flowTokenMatch = html.match(/"sFT":"([^"]+)"/);
		const sCtxMatch = html.match(/"sCtx":"([^"]+)"/);
		const canaryMatch = html.match(/"canary":"([^"]+)"/);

		//for debugging 
		console.log('flowToken:', flowTokenMatch?.[1]?.substring(0, 40));
		console.log('sCtx:', sCtxMatch?.[1]?.substring(0, 40));
		console.log('canary:', canaryMatch?.[1]?.substring(0, 40));


		if (!flowTokenMatch || !sCtxMatch) {
			logger.error('Could not find flowToken or sCtx in Microsoft login page');
			return null;
		}

		// extract cookies from response headers
		const rawCookies = response.headers?.['set-cookie'];
		const cookies = Array.isArray(rawCookies) ? rawCookies.map(c => c.split(';')[0]).join('; ') : '';

		return {
			flowToken: flowTokenMatch[1],
			sCtx: sCtxMatch[1],
			canary: canaryMatch?.[1] || '',
			cookies,
		};
	} catch (error) {
		logger.error(`getFreshTokens() error -> ${error?.toString()}`);
		return null;
	}
}


/**
 * Performs microsoft login verification to check if email exists
 * @param {string} email
 * @returns {Promise<{valid: boolean}>}
 */
async function microsoftLoginVerification(email) {
	/** @type {{valid: boolean}} */
	let result = { valid: false };

	try {
		// step 1 - get fresh tokens
		const tokens = await getFreshTokens();
		if (!tokens) {
			logger.error(`microsoftLoginVerification() could not get fresh tokens for ${email}`);
			return result;
		}

		// step 2 - build payload with fresh tokens
		const payload = {
			username: email,
			isOtherIdpSupported: true,
			checkPhones: false,
			isRemoteNGCSupported: true,
			isCookieBannerShown: false,
			isFidoSupported: true,
			originalRequest: tokens.sCtx,
			forceotclogin: false,
			isExternalFederationDisallowed: false,
			isRemoteConnectSupported: false,
			federationFlags: 0,
			isSignup: false,
			flowToken: tokens.flowToken,
			isAccessPassSupported: true,
		};

		// step 3 - build headers with fresh cookies and canary
		const options = {
			headers: {
				'User-Agent': userAgent.toString(),
				'Accept-Language': 'en-US,en;q=0.9',
				'Cookie': tokens.cookies,
				'Origin': 'https://login.microsoftonline.com',
				'Referer': LOGIN_PAGE_URL,
				'Sec-Fetch-Dest': 'empty',
				'Sec-Fetch-Mode': 'cors',
				'Sec-Fetch-Site': 'same-origin',
				'X-KL-Ajax-Request': 'Ajax_Request',
				'canary': tokens.canary,
				'client-request-id': crypto.randomUUID?.() || 'c2b81d3e-7275-4be9-a395-a20ce72b05a9',
				'hpgact': 1800,
				'hpgid': 1104,
			},
		};

		// step 4 - make the verification request
		const response = await axiosPost(CREDENTIAL_URL, payload, options);

		if (response && response.status === 200 && response?.data) {
			result.valid = !!(response?.data?.IfExistsResult === 5);
		} else {
			logger.error(`Non 200 status in microsoftLoginVerification() status -> ${response?.status}`);
		}

	} catch (error) {
		logger.error(`microsoftLoginVerification() error -> ${error?.toString()}`);
	} finally {
		return result;
	}
}

module.exports = microsoftLoginVerification;
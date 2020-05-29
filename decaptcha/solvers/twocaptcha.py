import scrapy
from twisted.internet.defer import inlineCallbacks, returnValue

from decaptcha.exceptions import CaptchaIncorrectlySolved, CaptchaSolveTimeout
from decaptcha.utils.download import download


class TwoCaptchaSolver(object):

    def __init__(self, crawler):
        self.crawler = crawler
        settings = crawler.settings
        self.apikey = settings.get('DECAPTCHA_TWOCAPTCHA_APIKEY')
        self.poll_times = settings.getint(
            'DECAPTCHA_TWOCAPTCHA_POLL_TIMES', 60
        )
        self.poll_delay = settings.getfloat(
            'DECAPTCHA_TWOCAPTCHA_POLL_DELAY', 2
        )
        self.api_url = 'http://2captcha.com/'

    @inlineCallbacks
    def solve(self, site_key, page_url, data_s=None):
        formdata = {
            'key': self.apikey,
            'method': 'userrecaptcha',
            'googlekey': site_key,
            'pageurl': page_url
        }
        if data_s:
            formdata['data-s'] = data_s
        request = scrapy.FormRequest(self.api_url + 'in.php', formdata=formdata)
        response = yield download(self.crawler, request)
        try:
            captcha_id = response.body.split('|')[1]
        except Exception:
            raise CaptchaIncorrectlySolved('2captcha returned non-parsable captcha request response ({}): {}'
                                           .format(response.status,
                                                   response.body))
        poll_url = self.api_url + 'res.php?key={}&action=get&id={}'.format(self.apikey, captcha_id)
        for retry in xrange(self.poll_times):
            poll_request = scrapy.Request(poll_url, dont_filter=True)
            poll_response = yield download(self.crawler, poll_request)
            if not 'CAPCHA_NOT_READY' in poll_response.body:
                try:
                    result = poll_response.body.split('|')[1]
                    returnValue(result)
                except Exception:
                    raise CaptchaIncorrectlySolved('2captcha returned non-parsable captcha poll response ({}): {}'
                                                   .format(poll_response.status,
                                                           poll_response.body))
        raise CaptchaSolveTimeout('2captcha did not solve CAPTCHA in time')

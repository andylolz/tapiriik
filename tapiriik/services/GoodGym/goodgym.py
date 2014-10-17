from datetime import timedelta
import requests
from django.core.urlresolvers import reverse

from tapiriik.services.service_base import ServiceAuthenticationType, ServiceBase
from tapiriik.services.sessioncache import SessionCache
from tapiriik.services.api import APIException, UserException, UserExceptionType

class GoodGymService(ServiceBase):
    # Short ID used everywhere in logging and DB storage
    ID = "goodgym"
    # Full display name given to users
    DisplayName = "GoodGym"
    # 2-3 letter abbreviated name
    DisplayAbbreviation = "GG"

    # One of ServiceAuthenticationType
    AuthenticationType = ServiceAuthenticationType.UsernamePassword

    # List of ActivityTypes
    SupportedActivities = None

    _sessionCache = SessionCache(lifetime=timedelta(minutes=30), freshen_on_get=True)
    _urlRoot = "http://www.goodgym.org"

    def _get_session(self, record=None, email=None, password=None, skip_cache=False):
        from tapiriik.auth.credential_storage import CredentialStore

        cached = self._sessionCache.Get(record.ExternalID if record else email)
        if cached and not skip_cache:
            return cached
        if record:
            #  longing for C style overloads...
            password = CredentialStore.Decrypt(record.ExtendedAuthorization["Password"])
            email = CredentialStore.Decrypt(record.ExtendedAuthorization["Email"])

        session = requests.Session()
        # self._rate_limit()

        payload = {'auth_key': email, 'password': password}
        r = requests.post('%s/auth/identity/callback' % self._urlRoot, data=payload, allow_redirects=False)
        print(r.headers['location'][6:13])
        if r.headers['location'][6:13] == 'failure':
            raise APIException("Invalid login", block=True, user_exception=UserException(UserExceptionType.Authorization, intervention_required=True))

        self._sessionCache.Set(record.ExternalID if record else email, session)
        # session.headers.update(self._obligatory_headers)
        return session

    def WebInit(self):
        self.UserAuthorizationURL = reverse("oauth_redirect", kwargs={"service": "goodgym"})

    # # Causes synchronizations to be skipped until...
    # #  - One is triggered (via IDs returned by ExternalIDsForPartialSyncTrigger or PollPartialSyncTrigger)
    # #  - One is necessitated (non-partial sync, possibility of uploading new activities, etc)
    # PartialSyncRequiresTrigger = False
    # # Timedelta for polling to happen at (or None for no polling)
    # PartialSyncTriggerPollInterval = None
    # # How many times to call the polling method per interval (this is for the multiple_index kwarg)
    # PartialSyncTriggerPollMultiple = 1

    # # Adds the Setup button to the service configuration pane, and not much else
    # Configurable = False
    # # Defaults for per-service configuration
    # ConfigurationDefaults = {}

    # # For the diagnostics dashboard
    # UserProfileURL = UserActivityURL = None

    def GenerateUserAuthorizationURL(self, level=None):
        full = level == "full"
        if full:
            sess = session.DropboxSession(DROPBOX_FULL_APP_KEY, DROPBOX_FULL_APP_SECRET, "dropbox")
        else:
            sess = session.DropboxSession(DROPBOX_APP_KEY, DROPBOX_APP_SECRET, "app_folder")

        reqToken = sess.obtain_request_token()
        redis.setex("dropbox:oauth:%s" % reqToken.key, pickle.dumps(reqToken), timedelta(hours=24))
        return sess.build_authorize_url(reqToken, oauth_callback=WEB_ROOT + reverse("oauth_return", kwargs={"service": "dropbox", "level": "full" if full else "normal"}))

    def Authorize(self, email, password):
        from tapiriik.auth.credential_storage import CredentialStore

        session = self._get_session(email=email, password=password)

        return (email, {}, {"Email": CredentialStore.Encrypt(email), "Password": CredentialStore.Encrypt(password)})

    def RevokeAuthorization(self, serviceRecord):
        raise NotImplementedError

    def DownloadActivityList(self, serviceRecord, exhaustive=False):
        raise NotImplementedError

    def DownloadActivity(self, serviceRecord, activity):
        raise NotImplementedError

    def UploadActivity(self, serviceRecord, activity):
        raise NotImplementedError

    def DeleteCachedData(self, serviceRecord):
        raise NotImplementedError

    def SubscribeToPartialSyncTrigger(self, serviceRecord):
        if self.PartialSyncRequiresTrigger:
            raise NotImplementedError
        else:
            raise InvalidServiceOperationException

    def UnsubscribeFromPartialSyncTrigger(self, serviceRecord):
        if self.PartialSyncRequiresTrigger:
            raise NotImplementedError
        else:
            raise InvalidServiceOperationException

    def ShouldForcePartialSyncTrigger(self, serviceRecord):
        if self.PartialSyncRequiresTrigger:
            return False
        else:
            raise InvalidServiceOperationException

    def PollPartialSyncTrigger(self, multiple_index):
        if self.PartialSyncRequiresTrigger and self.PartialSyncTriggerPollInterval:
            raise NotImplementedError
        else:
            raise InvalidServiceOperationException

    def ExternalIDsForPartialSyncTrigger(self, req):
        raise NotImplementedError

    def ConfigurationUpdating(self, serviceRecord, newConfig, oldConfig):
        pass

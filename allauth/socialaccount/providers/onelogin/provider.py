from allauth.account.models import EmailAddress
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider


class OneLoginAccount(ProviderAccount):
    def to_str(self):
        dflt = super(OneLoginAccount, self).to_str()
        return self.account.extra_data.get("name", dflt)


class OneLoginProvider(OAuth2Provider):
    id = "onelogin"
    name = "OneLogin"
    account_class = OneLoginAccount

    def get_default_scope(self):
        return ["openid", "profile", "email"]

    def extract_uid(self, data):
        return str(data["preferred_username"])

    def extract_extra_data(self, data):
        return data

    def extract_email_addresses(self, data):
        return [
            EmailAddress(
                email=data["email"], verified=bool(data["email_verified"]), primary=True
            )
        ]

    def extract_common_fields(self, data):
        return dict(
            email=data["email"],
            last_name=data["family_name"],
            first_name=data["given_name"],
        )


provider_classes = [OneLoginProvider]

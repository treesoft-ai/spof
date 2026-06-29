"""Global spoof and injection state for Spof (Thread-Local)."""

import sys
import threading
from types import ModuleType

class ThreadLocalState(ModuleType):
    def __init__(self, name):
        super().__init__(name)
        self._local = threading.local()

    def _get_local_attr(self, name, default_factory):
        if not hasattr(self._local, name):
            setattr(self._local, name, default_factory())
        return getattr(self._local, name)

    @property
    def spoof_dns_records(self):
        return self._get_local_attr('spoof_dns_records', list)

    @property
    def spoof_record_text(self):
        return self._get_local_attr('spoof_record_text', list)

    @property
    def spoof_url_responses(self):
        return self._get_local_attr('spoof_url_responses', dict)

    @property
    def spoof_cloud_responses(self):
        return self._get_local_attr('spoof_cloud_responses', list)

    @property
    def spoof_license_responses(self):
        return self._get_local_attr('spoof_license_responses', list)

    @property
    def spoof_tool_responses(self):
        return self._get_local_attr('spoof_tool_responses', list)

    @property
    def spoof_staging_responses(self):
        return self._get_local_attr('spoof_staging_responses', list)

    @property
    def spoof_role_responses(self):
        return self._get_local_attr('spoof_role_responses', list)

sys.modules[__name__] = ThreadLocalState(__name__)

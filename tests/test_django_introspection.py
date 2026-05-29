from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "django_introspection.py"
SPEC = importlib.util.spec_from_file_location("django_introspection", SCRIPT)
django_introspection = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(django_introspection)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class Pattern:
    def __init__(self, route: str) -> None:
        self._route = route


class UrlPattern:
    def __init__(self, route: str, callback, name: str) -> None:
        self.pattern = Pattern(route)
        self.callback = callback
        self.name = name


def install_django_stub() -> list[str]:
    modules: dict[str, types.ModuleType] = {}
    django = types.ModuleType("django")
    django.setup = lambda: None
    conf = types.ModuleType("django.conf")
    urls = types.ModuleType("django.urls")

    def path(route: str, callback, name: str = "") -> UrlPattern:
        return UrlPattern(route, callback, name)

    urls.path = path
    modules["django"] = django
    modules["django.conf"] = conf
    modules["django.urls"] = urls
    for name, module in modules.items():
        sys.modules[name] = module
    return list(modules)


class ApiView:
    permission_classes = ["IsAuthenticated"]
    authentication_classes = ["TokenAuthentication"]
    throttle_classes = ["ScopedRateThrottle"]
    serializer_class = "ApiSerializer"


def api_callback(request):
    return None


api_callback.cls = ApiView
api_callback.actions = {"get": "list"}


def uninstall_modules(names: list[str]) -> None:
    for name in names:
        sys.modules.pop(name, None)


def make_project(root: Path) -> None:
    write(root / "app" / "__init__.py", "")
    write(root / "app" / "views.py", "def health(request):\n    return None\nhealth.permission_classes = ['AllowAny']\nhealth.authentication_classes = ['SessionAuthentication']\nhealth.throttle_classes = ['UserRateThrottle']\nhealth.serializer_class = 'HealthSerializer'\n")
    write(
        root / "app" / "urls.py",
        "from django.urls import path\nfrom . import views\nurlpatterns = [path('health/', views.health, name='health')]\n",
    )
    write(root / "config" / "__init__.py", "")
    write(
        root / "config" / "settings.py",
        "SECRET_KEY = 'secret-value'\n"
        "DEBUG = False\n"
        "ALLOWED_HOSTS = ['example.com']\n"
        "ROOT_URLCONF = 'app.urls'\n"
        "INSTALLED_APPS = ['django.contrib.auth', 'rest_framework', 'app']\n"
        "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.middleware.csrf.CsrfViewMiddleware']\n"
        "AUTHENTICATION_BACKENDS = ['django.contrib.auth.backends.ModelBackend']\n"
        "class DefaultPermission: pass\nclass DefaultAuthentication: pass\nclass DefaultThrottle: pass\nclass DefaultSerializer: pass\n"
        "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': [DefaultPermission], 'DEFAULT_AUTHENTICATION_CLASSES': [DefaultAuthentication], 'DEFAULT_THROTTLE_CLASSES': [DefaultThrottle], 'DEFAULT_THROTTLE_RATES': {'user': '100/day', 'anon': '10/day'}, 'DEFAULT_SERIALIZER_CLASS': DefaultSerializer}\n"
        "DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql', 'PASSWORD': 'db-secret', 'HOST': 'db.local', 'USER': 'db-user', 'NAME': 'prod'}}\n"
        "CACHES = {'default': {'BACKEND': 'django.core.cache.backends.redis.RedisCache', 'LOCATION': 'redis://cache.local:6379/0'}}\n"
        "from pathlib import Path\nBASE_DIR = Path('/srv/app')\nTEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates']}]\n"
        "CSRF_TRUSTED_ORIGINS = ['https://admin.example.com']\n"
        "CORS_ALLOWED_ORIGINS = ['https://api.example.com']\n"
        "CORS_ALLOW_ALL_ORIGINS = True\n"
        "SESSION_COOKIE_SECURE = True\n"
        "CSRF_COOKIE_SECURE = True\n",
    )


class DjangoIntrospectionTest(unittest.TestCase):
    def test_collects_settings_and_urls_with_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            make_project(project)
            modules = install_django_stub()
            sys.path.insert(0, str(project))
            settings = importlib.import_module("config.settings")
            sys.modules["django.conf"].settings = settings
            result = django_introspection.collect(project, "config.settings")
            sys.path.remove(str(project))
            uninstall_modules(["app.urls", "app.views", "config.settings", "config", "app", *modules])

        self.assertEqual(result["settings"]["debug"], False)
        self.assertEqual(result["settings"]["allowed_hosts"], ["<redacted>"])
        self.assertIn("django.middleware.security.SecurityMiddleware", result["settings"]["middleware"])
        self.assertEqual(result["settings"]["secret_key"], "<redacted>")
        self.assertEqual(result["settings"]["databases"]["default"]["PASSWORD"], "<redacted>")
        self.assertEqual(result["settings"]["databases"]["default"]["HOST"], "<redacted>")
        self.assertEqual(result["settings"]["databases"]["default"]["USER"], "<redacted>")
        self.assertEqual(result["settings"]["databases"]["default"]["NAME"], "<redacted>")
        self.assertEqual(result["settings"]["caches"]["default"]["LOCATION"], "<redacted>")
        self.assertEqual(result["settings"]["templates"][0]["DIRS"], ["<redacted>"])
        self.assertEqual(result["settings"]["csrf_trusted_origins"], ["<redacted>"])
        self.assertEqual(result["settings"]["cors_allowed_origins"], ["<redacted>"])
        self.assertEqual(result["drf"]["default_permission_classes"], ["config.settings.DefaultPermission"])
        self.assertEqual(result["drf"]["default_authentication_classes"], ["config.settings.DefaultAuthentication"])
        self.assertEqual(result["drf"]["default_throttle_classes"], ["config.settings.DefaultThrottle"])
        self.assertEqual(result["drf"]["default_throttle_rates"], {"user": "100/day", "anon": "10/day"})
        self.assertEqual(result["drf"]["default_serializer_class"], "config.settings.DefaultSerializer")
        self.assertEqual(result["urls"][0]["pattern"], "health/")
        self.assertEqual(result["urls"][0]["name"], "health")
        self.assertTrue(result["urls"][0]["callback"].endswith("health"))
        self.assertEqual(result["urls"][0]["drf"]["permission_classes"], ["AllowAny"])
        self.assertEqual(result["urls"][0]["drf"]["serializer_class"], "HealthSerializer")

    def test_drf_metadata_uses_callback_cls_shape(self) -> None:
        rows = django_introspection.flatten_urls([UrlPattern("api/", api_callback, "api")])

        self.assertTrue(rows[0]["callback"].endswith("ApiView"))
        self.assertEqual(rows[0]["drf"]["permission_classes"], ["IsAuthenticated"])
        self.assertEqual(rows[0]["drf"]["authentication_classes"], ["TokenAuthentication"])
        self.assertEqual(rows[0]["drf"]["throttle_classes"], ["ScopedRateThrottle"])
        self.assertEqual(rows[0]["drf"]["serializer_class"], "ApiSerializer")
        self.assertEqual(rows[0]["drf"]["actions"], {"get": "list"})

    def test_writes_expected_f2_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            reports = Path(tmp) / "reports"
            make_project(project)
            modules = install_django_stub()
            sys.path.insert(0, str(project))
            settings = importlib.import_module("config.settings")
            sys.modules["django.conf"].settings = settings

            django_introspection.write_artifacts(project, "config.settings", reports)

            settings_content = (reports / "F2" / "django-settings.json").read_text()
            settings = json.loads(settings_content)
            urls = json.loads((reports / "F2" / "django-urls.json").read_text())
            sys.path.remove(str(project))
            uninstall_modules(["app.urls", "app.views", "config.settings", "config", "app", *modules])

        self.assertEqual(settings["settings_module"], "config.settings")
        self.assertEqual(urls["settings_module"], "config.settings")
        self.assertEqual(urls["urls"][0]["pattern"], "health/")
        self.assertNotIn("example.com", settings_content)

    def test_collect_restores_process_state(self) -> None:
        original_path = list(sys.path)
        original_settings = sys.modules.get("django.conf")
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            make_project(project)
            modules = install_django_stub()
            sys.path.insert(0, str(project))
            settings = importlib.import_module("config.settings")
            sys.modules["django.conf"].settings = settings
            sys.path.remove(str(project))

            django_introspection.collect(project, "config.settings")
            uninstall_modules(["app.urls", "app.views", "config.settings", "config", "app", *modules])
            if original_settings is not None:
                sys.modules["django.conf"] = original_settings

        self.assertEqual(sys.path, original_path)


if __name__ == "__main__":
    unittest.main()

from django.apps import AppConfig


class MyappConfig(AppConfig):
    name = 'myapp'

    def ready(self):
        # Load the database mirroring signal handlers when the app starts.
        import myapp.db_mirroring  # noqa: F401

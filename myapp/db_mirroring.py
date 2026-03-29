import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)
User = get_user_model()
MIRROR_DB_ALIAS = 'mysql'
MIRROR_APPS = {'myapp', 'auth'}


def should_mirror(sender, using):
    if using == MIRROR_DB_ALIAS:
        return False
    if MIRROR_DB_ALIAS not in settings.DATABASES:
        return False
    if not getattr(sender._meta, 'managed', True):
        return False
    if getattr(sender._meta, 'proxy', False):
        return False
    if sender._meta.app_label not in MIRROR_APPS:
        return False
    if sender._meta.app_label == 'auth' and sender is not User:
        return False
    return True


def ensure_user_exists_in_mysql(instance):
    if not hasattr(instance, '_meta'):
        return
    for field in instance._meta.get_fields():
        if field.many_to_one and field.related_model is User:
            try:
                user_obj = getattr(instance, field.name, None)
            except AttributeError:
                continue
            if not user_obj:
                continue
            if not User.objects.using(MIRROR_DB_ALIAS).filter(pk=user_obj.pk).exists():
                try:
                    user_obj.save(using=MIRROR_DB_ALIAS)
                except Exception as exc:
                    logger.warning(
                        'Failed to mirror User %s to %s: %s',
                        user_obj.pk,
                        MIRROR_DB_ALIAS,
                        exc,
                    )


@receiver(post_save)
def mirror_model_save(sender, instance, created, using, **kwargs):
    if not should_mirror(sender, using):
        return

    ensure_user_exists_in_mysql(instance)

    try:
        instance.save(using=MIRROR_DB_ALIAS)
    except Exception as exc:
        logger.warning(
            'MySQL mirror save failed for %s(%s) using %s: %s',
            sender.__name__,
            getattr(instance, 'pk', None),
            MIRROR_DB_ALIAS,
            exc,
        )

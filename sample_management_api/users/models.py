from enum import Flag
from django.contrib.auth.models import AbstractUser
from django.db.models import CharField
from django.db.models.enums import TextChoices
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from typing import AbstractSet
from django.urls import reverse
from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    class AccessLevel(models.TextChoices):
        CHEMIST = "Chemist", "Chemist"
        MANAGER = "Manager", "Manager"

    class Status(models.TextChoices):
        ACTIVE = "Active", "Active"
        SUSPENDED = "Suspended", "Suspended"
    email = models.CharField(max_length=255, null=True, blank=True)

    role = models.CharField(
        max_length=10, null=True, blank=True, choices=AccessLevel.choices
    )
    first_name = models.CharField(max_length=255, null=True, blank=True)
    last_name = models.CharField(null=False, blank=True, max_length=250)
    status = models.CharField(max_length=10, null=True, blank=True, choices=Status.choices)
    last_login = models.DateTimeField(auto_now_add=False, null=True)

    def get_absolute_url(self):
        """Get url for user"s detail view.

    Returns:
        str: URL for user detail.

    """
        return reverse("users:detail", kwargs={"username": self.username})

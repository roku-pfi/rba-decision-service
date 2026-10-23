"""SQLAlchemy models: the decisions read model and tenant policies.

The outbox is gone (ADR-0044): events leave through the Valkey journal, and the
event-publisher fills ``decisions`` from it.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeDecorator, Uuid


class GUID(TypeDecorator):
    """Platform-independent UUID type."""

    impl = Uuid
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PGUUID(as_uuid=True))
        return dialect.type_descriptor(Uuid(as_uuid=True))


class JSONType(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class Base(DeclarativeBase):
    pass


class DecisionRow(Base):
    __tablename__ = "decisions"
    # The console lists a tenant's (or a user's) newest decisions: without these
    # the list sorted every row of the tenant, 0.8 s at 120k rows.
    __table_args__ = (
        Index("ix_decisions_tenant_scored", "tenant_id", "scored_at"),
        Index("ix_decisions_tenant_user_scored", "tenant_id", "user_id", "scored_at"),
    )

    event_id: Mapped[UUID] = mapped_column(GUID(), primary_key=True)
    # ADR-0033: every read is filtered by tenant.
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    # The engine's verdict and what was applied (ADR-0034); they differ under MONITOR.
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    enforced_action: Mapped[str] = mapped_column(String(32), nullable=False)
    engine_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    # Country/ASN from the presenter override (ADR-0032).
    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    fallback: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reasons: Mapped[dict | list] = mapped_column(JSONType, nullable=False, default=list)
    features: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    # The login as observed (IP, country, network, device): what the console
    # shows next to the verdict. Nullable: rows before contracts 0.13.0 lack it.
    login: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    scored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Set by the event-publisher from the LoginConfirmedEvent (RF-11): the user
    # passed the step-up. Nullable, so kept databases get it added on startup.
    step_up_passed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TenantPolicyRow(Base):
    """One TenantPolicy per tenant (ADR-0033).

    Lives in the database rather than in a file inside the container, so every
    PDP replica reads the same policy and a restart loses nothing (RNF-05,
    RNF-10).
    """

    __tablename__ = "tenant_policies"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy: Mapped[dict] = mapped_column(JSONType, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

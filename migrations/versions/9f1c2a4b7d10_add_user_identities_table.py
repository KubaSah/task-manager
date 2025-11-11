"""add user_identities table and backfill from existing users

Revision ID: 9f1c2a4b7d10
Revises: 7b2f3d1c9a3a
Create Date: 2025-11-11

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column

# revision identifiers, used by Alembic.
revision = '9f1c2a4b7d10'
down_revision = '7b2f3d1c9a3a'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'user_identities',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('provider_id', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('provider', 'provider_id', name='uq_identity_provider_id'),
    )
    op.create_index('ix_identity_user_provider', 'user_identities', ['user_id', 'provider'])

    # Backfill: create identity rows for existing users with provider/provider_id
    bind = op.get_bind()
    users = list(bind.execute(sa.text('SELECT id, provider, provider_id, created_at FROM users')))
    for u in users:
        if u.provider and u.provider_id:
            bind.execute(
                sa.text('INSERT OR IGNORE INTO user_identities (user_id, provider, provider_id, created_at) VALUES (:uid, :prov, :pid, :created_at)')
                , {
                    'uid': u.id,
                    'prov': u.provider,
                    'pid': u.provider_id,
                    'created_at': u.created_at,
                }
            )


def downgrade():
    op.drop_index('ix_identity_user_provider', table_name='user_identities')
    op.drop_table('user_identities')

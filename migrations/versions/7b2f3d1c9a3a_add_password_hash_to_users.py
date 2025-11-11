"""add password_hash to users

Revision ID: 7b2f3d1c9a3a
Revises: 3570ba382479
Create Date: 2025-11-11

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7b2f3d1c9a3a'
down_revision = '3570ba382479'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('password_hash', sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column('users', 'password_hash')

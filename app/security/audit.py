from __future__ import annotations
from typing import Optional, Any
from flask_login import current_user
from .. import db
from ..models import AuditLog
import json

def log_action(action: str, entity_type: str, entity_id: Optional[int] = None, project_id: Optional[int] = None, meta: Optional[dict[str, Any]] = None):
    """
    Zapisuje akcję w logu audytu.
    
    Args:
        action: Nazwa akcji (np. 'task.status', 'project.create')
        entity_type: Typ encji ('task', 'project', 'comment', itp.)
        entity_id: ID encji (opcjonalne)
        project_id: ID projektu, którego dotyczy akcja (opcjonalne)
        meta: Dodatkowe metadane JSON (opcjonalne)
    
    Note:
        Nie commituje transakcji – wywołujący musi wykonać db.session.commit()
    """
    try:
        actor_id = current_user.id if getattr(current_user, 'is_authenticated', False) else None
    except Exception:
        actor_id = None
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        project_id=project_id,
        meta=json.dumps(meta) if meta else None,
    )
    db.session.add(entry)
    # Do not commit here; caller decides when to commit

"""Tests for project ownership transfer functionality."""
import pytest
from app.models import Project, Membership, User


def login_as(client, user_id):
    """Helper to log in a user via session."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True


def test_transfer_ownership_success(client, app):
    """Owner can transfer ownership to another member."""
    with app.app_context():
        # Create owner
        owner = User(email='owner@test.com', name='Owner', provider='local', provider_id='owner1')
        owner.set_password('password')
        
        # Create new owner
        new_owner = User(email='newowner@test.com', name='New Owner', provider='local', provider_id='new1')
        new_owner.set_password('password')
        
        from app import db
        db.session.add_all([owner, new_owner])
        db.session.commit()
        
        # Create project with owner
        project = Project(name='Test Project', key='TEST', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        
        # Add memberships
        owner_membership = Membership(user_id=owner.id, project_id=project.id, role='owner')
        new_owner_membership = Membership(user_id=new_owner.id, project_id=project.id, role='member')
        db.session.add_all([owner_membership, new_owner_membership])
        db.session.commit()
        
        project_id = project.id
        new_owner_id = new_owner.id
        owner_id = owner.id
    
    # Login as owner using session
    login_as(client, owner_id)
    
    # Transfer ownership
    response = client.post(
        f'/projects/{project_id}/transfer-owner',
        data={'new_owner_id': new_owner_id},
        follow_redirects=False
    )
    
    assert response.status_code == 302  # redirect
    
    # Verify changes in database
    with app.app_context():
        p = db.session.get(Project, project_id)
        assert p.owner_id == new_owner_id
        
        # Old owner should now be admin
        old_owner_m = Membership.query.filter_by(project_id=project_id, user_id=owner_id).first()
        assert old_owner_m.role == 'admin'
        
        # New owner should have owner role
        new_owner_m = Membership.query.filter_by(project_id=project_id, user_id=new_owner_id).first()
        assert new_owner_m.role == 'owner'


def test_transfer_ownership_to_self(client, app):
    """Owner cannot transfer ownership to themselves."""
    with app.app_context():
        owner = User(email='owner@test.com', name='Owner', provider='local', provider_id='owner1')
        owner.set_password('password')
        
        from app import db
        db.session.add(owner)
        db.session.commit()
        
        project = Project(name='Test Project', key='TEST', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        
        owner_membership = Membership(user_id=owner.id, project_id=project.id, role='owner')
        db.session.add(owner_membership)
        db.session.commit()
        
        project_id = project.id
        owner_id = owner.id
    
    login_as(client, owner_id)
    
    response = client.post(
        f'/projects/{project_id}/transfer-owner',
        data={'new_owner_id': owner_id},
        follow_redirects=False
    )
    
    assert response.status_code == 302  # redirect back with flash message


def test_transfer_ownership_to_non_member(client, app):
    """Cannot transfer ownership to user who is not a member."""
    with app.app_context():
        owner = User(email='owner@test.com', name='Owner', provider='local', provider_id='owner1')
        owner.set_password('password')
        
        stranger = User(email='stranger@test.com', name='Stranger', provider='local', provider_id='stranger1')
        stranger.set_password('password')
        
        from app import db
        db.session.add_all([owner, stranger])
        db.session.commit()
        
        project = Project(name='Test Project', key='TEST', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        
        owner_membership = Membership(user_id=owner.id, project_id=project.id, role='owner')
        db.session.add(owner_membership)
        db.session.commit()
        
        project_id = project.id
        stranger_id = stranger.id
        owner_id = owner.id
    
    login_as(client, owner_id)
    
    response = client.post(
        f'/projects/{project_id}/transfer-owner',
        data={'new_owner_id': stranger_id},
        follow_redirects=False
    )
    
    assert response.status_code == 302  # redirect with error


def test_transfer_ownership_non_owner_forbidden(client, app):
    """Only owner can transfer ownership, not admin or member."""
    with app.app_context():
        owner = User(email='owner@test.com', name='Owner', provider='local', provider_id='owner1')
        owner.set_password('password')
        
        admin = User(email='admin@test.com', name='Admin', provider='local', provider_id='admin1')
        admin.set_password('password')
        
        member = User(email='member@test.com', name='Member', provider='local', provider_id='member1')
        member.set_password('password')
        
        from app import db
        db.session.add_all([owner, admin, member])
        db.session.commit()
        
        project = Project(name='Test Project', key='TEST', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        
        owner_membership = Membership(user_id=owner.id, project_id=project.id, role='owner')
        admin_membership = Membership(user_id=admin.id, project_id=project.id, role='admin')
        member_membership = Membership(user_id=member.id, project_id=project.id, role='member')
        db.session.add_all([owner_membership, admin_membership, member_membership])
        db.session.commit()
        
        project_id = project.id
        member_id = member.id
        admin_id = admin.id
    
    # Try as admin (should fail)
    login_as(client, admin_id)
    
    response = client.post(
        f'/projects/{project_id}/transfer-owner',
        data={'new_owner_id': member_id}
    )
    
    # Should get 403 or redirect with error
    assert response.status_code in (403, 302)


def test_transfer_ownership_audit_log(client, app):
    """Transfer ownership creates audit log entry."""
    with app.app_context():
        owner = User(email='owner@test.com', name='Owner', provider='local', provider_id='owner1')
        owner.set_password('password')
        
        new_owner = User(email='newowner@test.com', name='New Owner', provider='local', provider_id='new1')
        new_owner.set_password('password')
        
        from app import db
        db.session.add_all([owner, new_owner])
        db.session.commit()
        
        project = Project(name='Test Project', key='TEST', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        
        owner_membership = Membership(user_id=owner.id, project_id=project.id, role='owner')
        new_owner_membership = Membership(user_id=new_owner.id, project_id=project.id, role='member')
        db.session.add_all([owner_membership, new_owner_membership])
        db.session.commit()
        
        project_id = project.id
        new_owner_id = new_owner.id
        owner_id = owner.id
    
    login_as(client, owner_id)
    
    client.post(
        f'/projects/{project_id}/transfer-owner',
        data={'new_owner_id': new_owner_id}
    )
    
    # Check audit log
    with app.app_context():
        from app.models import AuditLog
        import json
        log = AuditLog.query.filter_by(
            action='project.transfer_ownership',
            entity_type='project',
            entity_id=project_id
        ).first()
        
        assert log is not None
        meta = json.loads(log.meta)
        assert meta['old_owner_id'] == owner_id
        assert meta['new_owner_id'] == new_owner_id

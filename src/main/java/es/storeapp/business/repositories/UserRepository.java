package es.storeapp.business.repositories;

import es.storeapp.business.entities.User;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository extends AbstractRepository<User> {

    private static final String FIND_USER_BY_EMAIL_QUERY =
            "SELECT u FROM User u WHERE u.email = :email";

    private static final String COUNT_USER_BY_EMAIL_QUERY =
            "SELECT COUNT(u) FROM User u WHERE u.email = :email";

    // Eliminar esta consulta vulnerable
    // private static final String LOGIN_QUERY = "SELECT u FROM User u WHERE u.email = ''{0}'' AND u.password = ''{1}''";

    public User findByEmail(String email) {
        try {
            TypedQuery<User> query = entityManager.createQuery(FIND_USER_BY_EMAIL_QUERY, User.class);
            query.setParameter("email", email);
            return query.getSingleResult();
        } catch (NoResultException e) {
            logger.warn("User not found with email: {}", email);
            return null;
        } catch (Exception e) {
            logger.error("Error finding user by email: {}", email, e);
            return null;
        }
    }

    public boolean existsUser(String email) {
        try {
            Query query = entityManager.createQuery(COUNT_USER_BY_EMAIL_QUERY);
            query.setParameter("email", email);
            Long count = (Long) query.getSingleResult();
            return (count > 0);
        } catch (Exception e) {
            logger.error("Error checking if user exists: {}", email, e);
            return false;
        }
    }

    // Se mantiene la funcion para que no rompa pero no se le da funcionalidad
    public User findByEmailAndPassword(String email, String password) {
        throw new UnsupportedOperationException(
                "This method is insecure. Use findByEmail() and verify password in service layer instead.");
    }
}
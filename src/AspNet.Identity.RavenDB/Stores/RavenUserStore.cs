using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Identity.RavenDB.Entities;
using Microsoft.AspNet.Identity;
using Raven.Client;

namespace AspNet.Identity.RavenDB.Stores
{
    public class RavenUserStore<TUser> : IUserStore<TUser>, IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IQueryableUserStore<TUser>, IUserTwoFactorStore<TUser, string>, IUserLockoutStore<TUser, string>, IUserEmailStore<TUser>, IUserPhoneNumberStore<TUser>, IDisposable where TUser : RavenUser
    {
        readonly bool _disposeDocumentSession;
        protected IAsyncDocumentSession _documentSession;
        readonly IDocumentStore _documentStore;
        string _databaseName;

        public RavenUserStore(IDocumentStore documentStore, string databaseName) : this(documentStore, databaseName, true)
        {}

        public RavenUserStore(IDocumentStore documentStore, string databaseName, bool disposeDocumentSession)
        {
            if (documentStore == null)
            {
                throw new ArgumentNullException(nameof(documentStore));
            }

            //if (documentStore.Advanced.UseOptimisticConcurrency == false)
            //{
            //    throw new NotSupportedException("Optimistic concurrency disabled 'IAsyncDocumentSession' instance is not supported because the uniqueness of the username and the e-mail needs to ensured. Please enable optimistic concurrency by setting the 'Advanced.UseOptimisticConcurrency' property on the 'IAsyncDocumentSession' instance and leave the optimistic concurrency enabled on the session till the end of its lifetime. Otherwise, you will have a chance of ending up overriding an existing user's data if a new user tries to register with the username of that existing user.");
            //}

            _databaseName = databaseName;
            _documentStore = documentStore;
            OpenAsyncSession();

            _disposeDocumentSession = disposeDocumentSession;
        }

        void OpenAsyncSession()
        {
            _documentSession = _documentStore.OpenAsyncSession(_databaseName);
            _documentSession.Advanced.UseOptimisticConcurrency = true;
        }

        // IQueryableUserStore

        public IQueryable<TUser> Users => _documentSession.Query<TUser>();

        // IUserClaimStore

        public Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult<IList<Claim>>(user.Claims.Select(clm => new Claim(clm.ClaimType, clm.ClaimValue))
                .ToList());
        }

        public Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            user.AddClaim(claim);
            return Task.FromResult(0);
        }

        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var userClaim = user.Claims.FirstOrDefault(clm => clm.ClaimType == claim.Type && clm.ClaimValue == claim.Value);

            if (userClaim != null)
            {
                user.RemoveClaim(userClaim);
            }

            return Task.FromResult(0);
        }

        // IUserEmailStore

        public async Task<TUser> FindByEmailAsync(string email)
        {
            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }

            var keyToLookFor = RavenUserEmail.GenerateKey(email);

            var ravenUserEmail = await _documentSession.Include<RavenUserEmail, TUser>(usrEmail => usrEmail.UserId)
                .LoadAsync(keyToLookFor)
                .ConfigureAwait(false);

            return ravenUserEmail != null ? await _documentSession.LoadAsync<TUser>(ravenUserEmail.UserId)
                .ConfigureAwait(false) : default(TUser);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Email);
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.Email == null)
            {
                throw new InvalidOperationException("Cannot get the confirmation status of the e-mail because user doesn't have an e-mail.");
            }

            var confirmation = await GetUserEmailConfirmationAsync(user.Email)
                .ConfigureAwait(false);

            return confirmation != null;
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (email == null)
                throw new ArgumentNullException(nameof(email));

            user.SetEmail(email);
            var ravenUserEmail = new RavenUserEmail(email, user.Id);

            return _documentSession.StoreAsync(ravenUserEmail);
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.Email == null)
            {
                throw new InvalidOperationException("Cannot set the confirmation status of the e-mail because user doesn't have an e-mail.");
            }

            var userEmail = await GetUserEmailAsync(user.Email)
                .ConfigureAwait(false);
            if (userEmail == null)
            {
                throw new InvalidOperationException("Cannot set the confirmation status of the e-mail because user doesn't have an e-mail as RavenUserEmail document.");
            }

            if (confirmed)
            {
                userEmail.SetConfirmed();
            }
            else
            {
                userEmail.SetUnconfirmed();
            }
        }

        // IUserLockoutStore

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (user.LockoutEndDate == null)
                throw new InvalidOperationException("LockoutEndDate has no value.");

            return Task.FromResult(user.LockoutEndDate.Value);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockUntil(lockoutEnd);
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // NOTE: Not confortable to do this like below but this will work out for the intended scenario
            //       + RavenDB doesn't have a reliable solution for $inc update as MongoDB does.
            user.IncrementAccessFailedCount();
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.ResetAccessFailedCount();
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsLockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (enabled)
            {
                user.EnableLockout();
            }
            else
            {
                user.DisableLockout();
            }

            return Task.FromResult(0);
        }

        // IUserLoginStore

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult<IList<UserLoginInfo>>(user.Logins.Select(login => new UserLoginInfo(login.LoginProvider, login.ProviderKey))
                .ToList());
        }

        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var keyToLookFor = RavenUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey);
            var ravenUserLogin = await _documentSession.Include<RavenUserLogin, TUser>(usrLogin => usrLogin.UserId)
                .LoadAsync(keyToLookFor)
                .ConfigureAwait(false);

            return ravenUserLogin != null ? await _documentSession.LoadAsync<TUser>(ravenUserLogin.UserId)
                .ConfigureAwait(false) : default(TUser);
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var ravenUserLogin = new RavenUserLogin(user.Id, login);
            await _documentSession.StoreAsync(ravenUserLogin)
                .ConfigureAwait(false);
            user.AddLogin(ravenUserLogin);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var keyToLookFor = RavenUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey);
            var ravenUserLogin = await _documentSession.LoadAsync<RavenUserLogin>(keyToLookFor)
                .ConfigureAwait(false);
            if (ravenUserLogin != null)
            {
                _documentSession.Delete(ravenUserLogin);
            }

            var userLogin = user.Logins.FirstOrDefault(lgn => lgn.Id.Equals(keyToLookFor, StringComparison.InvariantCultureIgnoreCase));
            if (userLogin != null)
            {
                user.RemoveLogin(userLogin);
            }
        }

        // IUserPasswordStore

        public Task<string> GetPasswordHashAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.SetPasswordHash(passwordHash);
            return Task.FromResult(0);
        }

        // IUserPhoneNumberStore

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PhoneNumber);
        }

        public async Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.PhoneNumber == null)
            {
                throw new InvalidOperationException("Cannot get the confirmation status of the phone number because user doesn't have a phone number.");
            }

            var confirmation = await GetUserPhoneNumberConfirmationAsync(user.PhoneNumber)
                .ConfigureAwait(false);

            return confirmation != null;
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (phoneNumber == null)
                throw new ArgumentNullException(nameof(phoneNumber));

            user.SetPhoneNumber(phoneNumber);
            var ravenUserPhoneNumber = new RavenUserPhoneNumber(phoneNumber, user.Id);

            return _documentSession.StoreAsync(ravenUserPhoneNumber);
        }

        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.PhoneNumber == null)
            {
                throw new InvalidOperationException("Cannot set the confirmation status of the phone number because user doesn't have a phone number.");
            }

            var userPhoneNumber = await GetUserPhoneNumberAsync(user.Email)
                .ConfigureAwait(false);
            if (userPhoneNumber == null)
            {
                throw new InvalidOperationException("Cannot set the confirmation status of the phone number because user doesn't have a phone number as RavenUserPhoneNumber document.");
            }

            if (confirmed)
            {
                userPhoneNumber.SetConfirmed();
            }
            else
            {
                userPhoneNumber.SetUnconfirmed();
            }
        }

        // IUserSecurityStampStore

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.SetSecurityStamp(stamp);
            return Task.FromResult(0);
        }

        // IUserStore

        /// <remarks>
        ///     This method doesn't perform uniquness. That's the responsibility of the session provider.
        /// </remarks>
        public async Task CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.UserName == null)
            {
                throw new InvalidOperationException("Cannot create user as the 'UserName' property is null on user parameter.");
            }

            await _documentSession.StoreAsync(user)
                .ConfigureAwait(false);
            await _documentSession.SaveChangesAsync()
                .ConfigureAwait(false);
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            if (userId == null)
                throw new ArgumentNullException(nameof(userId));

            return _documentSession.LoadAsync<TUser>(userId);
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            if (userName == null)
                throw new ArgumentNullException(nameof(userName));

            OpenAsyncSession();

            return _documentSession.LoadAsync<TUser>(RavenUser.GenerateKey(userName));
        }

        /// <remarks>
        ///     This method assumes that incomming TUser parameter is tracked in the session. So, this method literally behaves as
        ///     SaveChangeAsync
        /// </remarks>
        public Task UpdateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _documentSession.SaveChangesAsync();
        }

        public Task DeleteAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            _documentSession.Delete(user);
            return _documentSession.SaveChangesAsync();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // IUserTwoFactorStore

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsTwoFactorEnabled);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (enabled)
            {
                user.EnableTwoFactorAuthentication();
            }
            else
            {
                user.DisableTwoFactorAuthentication();
            }

            return Task.FromResult(0);
        }

        // Dispose

        protected void Dispose(bool disposing)
        {
            if (_disposeDocumentSession && disposing)
            {
                _documentSession?.Dispose();
            }
        }

        // privates

        Task<RavenUserEmail> GetUserEmailAsync(string email)
        {
            var keyToLookFor = RavenUserEmail.GenerateKey(email);
            return _documentSession.LoadAsync<RavenUserEmail>(keyToLookFor);
        }

        Task<RavenUserPhoneNumber> GetUserPhoneNumberAsync(string phoneNumber)
        {
            var keyToLookFor = RavenUserPhoneNumber.GenerateKey(phoneNumber);
            return _documentSession.LoadAsync<RavenUserPhoneNumber>(keyToLookFor);
        }

        async Task<ConfirmationRecord> GetUserEmailConfirmationAsync(string email)
        {
            var userEmail = await GetUserEmailAsync(email)
                .ConfigureAwait(false);

            return userEmail?.ConfirmationRecord;
        }

        async Task<ConfirmationRecord> GetUserPhoneNumberConfirmationAsync(string phoneNumber)
        {
            var userPhoneNumber = await GetUserPhoneNumberAsync(phoneNumber)
                .ConfigureAwait(false);

            return userPhoneNumber?.ConfirmationRecord;
        }
    }
}
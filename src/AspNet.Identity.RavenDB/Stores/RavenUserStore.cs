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
        readonly string _databaseName;
        
        public RavenUserStore(IDocumentStore documentStore, string databaseName, bool disposeDocumentSession = true)
        {
            _databaseName = databaseName;
            _documentStore = documentStore ?? throw new ArgumentNullException(nameof(documentStore));
            _documentStore.Conventions.AllowQueriesOnId = true;
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

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult<IList<Claim>>(user.Claims.Select(clm => new Claim(clm.ClaimType, clm.ClaimValue)).ToList());
        }

        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            user.AddClaim(claim);
            await Task.FromResult(0);
        }

        public async Task RemoveClaimAsync(TUser user, Claim claim)
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

            await Task.FromResult(0);
        }

        // IUserEmailStore

        public async Task<TUser> FindByEmailAsync(string email)
        {
            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }

            var keyToLookFor = RavenUserEmail.GenerateKey(email);

            //var ravenUserEmail = await _documentSession.Include<RavenUserEmail, TUser>(usrEmail => usrEmail.UserId)
            //    .LoadAsync(keyToLookFor)
            //    .ConfigureAwait(false);

            var ravenUserEmail = await _documentSession.Query<RavenUserEmail>()
                .Include<RavenUserEmail, TUser>(usrEmail => usrEmail.UserId)
                .SingleOrDefaultAsync(rue => rue.Id == keyToLookFor)
                .ConfigureAwait(false);

            return ravenUserEmail != null ? await _documentSession.Query<TUser>().SingleOrDefaultAsync(u => u.Id == ravenUserEmail.UserId) //.LoadAsync<TUser>(ravenUserEmail.UserId)
                .ConfigureAwait(false) : default;
        }

        public async Task<string> GetEmailAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.Email);
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

            var confirmation = await GetUserEmailConfirmationAsync(user.Email).ConfigureAwait(false);

            return confirmation != null;
        }

        public async Task SetEmailAsync(TUser user, string email)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (email == null)
                throw new ArgumentNullException(nameof(email));

            user.SetEmail(email);
            var ravenUserEmail = new RavenUserEmail(email, user.Id);

            await _documentSession.StoreAsync(ravenUserEmail);
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

        public async Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (user.LockoutEndDate == null)
                throw new InvalidOperationException("LockoutEndDate has no value.");

            return await Task.FromResult(user.LockoutEndDate.Value);
        }

        public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockUntil(lockoutEnd);
            await Task.FromResult(0);
        }

        public async Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // NOTE: Not confortable to do this like below but this will work out for the intended scenario
            //       + RavenDB doesn't have a reliable solution for $inc update as MongoDB does.
            user.IncrementAccessFailedCount();
            return await Task.FromResult(user.AccessFailedCount);
        }

        public async Task ResetAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.ResetAccessFailedCount();
            await Task.FromResult(0);
        }

        public async Task<int> GetAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.AccessFailedCount);
        }

        public async Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.IsLockoutEnabled);
        }

        public async Task SetLockoutEnabledAsync(TUser user, bool enabled)
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

            await Task.FromResult(0);
        }

        // IUserLoginStore

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return await Task.FromResult<IList<UserLoginInfo>>(user.Logins.Select(login => new UserLoginInfo(login.LoginProvider, login.ProviderKey))
                .ToList());
        }

        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var keyToLookFor = RavenUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey);
            //var ravenUserLogin = await _documentSession.Include<RavenUserLogin, TUser>(usrLogin => usrLogin.UserId)
            //    .LoadAsync(keyToLookFor)
            //    .ConfigureAwait(false);

            var ravenUserLogin = await _documentSession.Query<RavenUserLogin>()
                .Include<RavenUserLogin, TUser>(usrLogin => usrLogin.UserId)
                .SingleOrDefaultAsync(rul => rul.Id == keyToLookFor)
                .ConfigureAwait(false);

            return ravenUserLogin != null ? await _documentSession.Query<TUser>().SingleOrDefaultAsync(u => u.Id == ravenUserLogin.UserId) //.LoadAsync<TUser>(ravenUserLogin.UserId)
                .ConfigureAwait(false) : default;
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var ravenUserLogin = new RavenUserLogin(user.Id, login);
            await _documentSession.StoreAsync(ravenUserLogin).ConfigureAwait(false);

            user.AddLogin(ravenUserLogin);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var keyToLookFor = RavenUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey);
            //var ravenUserLogin = await _documentSession.LoadAsync<RavenUserLogin>(keyToLookFor).ConfigureAwait(false);
            var ravenUserLogin = await _documentSession.Query<RavenUserLogin>().SingleOrDefaultAsync(u => u.Id == keyToLookFor).ConfigureAwait(false);

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

        public async Task<string> GetPasswordHashAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.PasswordHash);
        }

        public async Task<bool> HasPasswordAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.PasswordHash != null);
        }

        public async Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.SetPasswordHash(passwordHash);
            await Task.FromResult(0);
        }

        // IUserPhoneNumberStore

        public async Task<string> GetPhoneNumberAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.PhoneNumber);
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

        public async Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (phoneNumber == null)
                throw new ArgumentNullException(nameof(phoneNumber));

            user.SetPhoneNumber(phoneNumber);
            var ravenUserPhoneNumber = new RavenUserPhoneNumber(phoneNumber, user.Id);

            await _documentSession.StoreAsync(ravenUserPhoneNumber);
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

        public async Task<string> GetSecurityStampAsync(TUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return await Task.FromResult(user.SecurityStamp);
        }

        public async Task SetSecurityStampAsync(TUser user, string stamp)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.SetSecurityStamp(stamp);
            await Task.FromResult(0);
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

            await _documentSession.StoreAsync(user).ConfigureAwait(false);
            await _documentSession.SaveChangesAsync().ConfigureAwait(false);
        }

        public async Task<TUser> FindByIdAsync(string userId)
        {
            if (userId == null)
                throw new ArgumentNullException(nameof(userId));

            return await _documentSession.Query<TUser>().SingleOrDefaultAsync(u => u.Id == userId);
            //return _documentSession.LoadAsync<TUser>(userId);
        }

        public async Task<TUser> FindByNameAsync(string userName)
        {
            if (userName == null)
                throw new ArgumentNullException(nameof(userName));

            OpenAsyncSession();

            var key = RavenUser.GenerateKey(userName);
            var user = await _documentSession.Query<TUser>().SingleOrDefaultAsync(u => u.Id == key);

            return user;
            //return _documentSession.LoadAsync<TUser>(RavenUser.GenerateKey(userName));
        }

        /// <remarks>
        ///     This method assumes that incomming TUser parameter is tracked in the session. So, this method literally behaves as
        ///     SaveChangeAsync
        /// </remarks>
        public async Task UpdateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await _documentSession.SaveChangesAsync();
        }

        public async Task DeleteAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            _documentSession.Delete(user);
            await _documentSession.SaveChangesAsync();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // IUserTwoFactorStore

        public async Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.IsTwoFactorEnabled);
        }

        public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
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

            await Task.FromResult(0);
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
            //return _documentSession.LoadAsync<RavenUserEmail>(keyToLookFor);
            return _documentSession.Query<RavenUserEmail>().SingleOrDefaultAsync(u => u.Id == keyToLookFor);
        }

        Task<RavenUserPhoneNumber> GetUserPhoneNumberAsync(string phoneNumber)
        {
            var keyToLookFor = RavenUserPhoneNumber.GenerateKey(phoneNumber);
            //return _documentSession.LoadAsync<RavenUserPhoneNumber>(keyToLookFor);
            return _documentSession.Query<RavenUserPhoneNumber>().SingleOrDefaultAsync(u => u.Id == keyToLookFor);
        }

        async Task<ConfirmationRecord> GetUserEmailConfirmationAsync(string email)
        {
            var userEmail = await GetUserEmailAsync(email).ConfigureAwait(false);

            return userEmail?.ConfirmationRecord;
        }

        async Task<ConfirmationRecord> GetUserPhoneNumberConfirmationAsync(string phoneNumber)
        {
            var userPhoneNumber = await GetUserPhoneNumberAsync(phoneNumber).ConfigureAwait(false);

            return userPhoneNumber?.ConfirmationRecord;
        }
    }
}
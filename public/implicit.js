hash = window.location.hash.substring(1)
fetch('',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: hash
    })
    .then(res => {
      if (res.status === 200) {
        return res.text();
      } else {
        throw Error('OIDC login failed');
      }
    })
    .then(x => {
      location.href = new URL(location).searchParams.get('rd');
    })
    .catch(err => {
      document.body.innerHTML = '';
      const thankText = document.createElement('p');
      thankText.innerText = 'There was a problem while validating your credentials';
      const logoutButton = document.createElement('button');
      logoutButton.innerText = 'Log out';
      logoutButton.addEventListener('click', () => {
        keycloak.logout();
      });
      document.body.appendChild(thankText);
      document.body.appendChild(logoutButton);
    })

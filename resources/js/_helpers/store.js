import Vuex from "vuex";
import Vue from "vue";


Vue.use(Vuex)

export const store = new Vuex.Store({
    state: {
        data: {},
        ready: 1,
    },
    mutations: {
        refreshUser (state) {
            state.ready++;
            fetch('/api/whoami', {
                method: 'GET',
                headers: {
                    'content-type': 'application/json',
                    'Authorization' : 'Bearer '+localStorage.token
                }
            })
                .then(res => res.json())
                .then(res => {
                    state.data.user = res.success.user;
                    state.ready--;
                })
                .catch(error => {
                    console.log(error);
                    state.data.user = null;
                    state.ready--;
                    localStorage.removeItem('token')
                })

        },
        getData (state) {
            fetch('/api/location', {
                method: 'GET',
                headers: {
                    'content-type': 'application/json',
                    'Authorization' : 'Bearer '+localStorage.token
                }
            })
                .then(res => res.json())
                .then(res => {
                    state.data.locations = res.success;
                    state.ready--;
                })
                .catch(error => {
                    console.log(error);
                    state.data.locations = null;
                })

        },
        clearData (state) {
            state.data = {};
            localStorage.removeItem('token')
        },
        clearUser (state) {
            state.data.user = null;
            localStorage.removeItem('token')
        }
    },
    getters: {
        data: state => state.data,
        locations: state => state.data.locations,
        ready: state => state.ready === 0
    }
});

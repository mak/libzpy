#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import re,fnmatch

data = { 
 'Alior' : [
     'https://aliorbank.pl/hades/do/Login'
 ],
 'Pekao S.A.' : [
     'https://www.pekao24.pl',
     'https://www.prepaid.pekao24.pl',
     'https://www.cdm24.pl',
     'https://www.pekaofirma24.pl/do/login;jsessionid=',
     'https://www.pekaobiznes24.pl/do/login'
 ],
 'BGK' : [
     'https://www.zleceniaplatnosci.bgk.pl/BGKSSO/Login.aspx?redirect',
     'https://www.bgk24biznes.pl/',
     'https://repozytorium.bgk.com.pl/'
 ],
 'BOŚ' : [
     'https://bosbank24.pl/twojekonto',
     'https://bosbank24.pl/iboss',
     'https://bosbank24.pl/bosfaktor/login.jsf'
 ],
 'Bank Pocztowy' : [
     'https://www.pocztowy24.pl/',
     'https://www.pocztowy24biznes.pl/web/guest/home',
     'https://e-wniosek.pocztowy.pl/lokaty-online/index.php'
 ],
 'BNP Paribas Bank Polska S.A.' : [
     'https://planet.bnpparibas.pl/hades/do/Login',
     'https://biznesplanet.bnpparibas.pl/hades/do/Login',
     'https://planet.bnpparibas.pl/hades/do/Login'
 ],
 'Credit Agricole Bank Polska S.A.' : [
     'https://e-bank.credit-agricole.pl/',
     'https://firmabank.credit-agricole.pl/mt-front/'
 ],
 'Deutsche Bank' : [
     'https://ebank.db-pbc.pl/auth/login.jsp',
     'https://ebusinessbank.db-pbc.pl/auth/login.jsp',
     'https://makler.dbmakler.pl/',
     'https://webfaktor.db-pbc.pl/login.jsf',
     'https://autobahn.db.com/',
     'https://db-direct.db.com/u/eb/Login_Main.serv',
     'https://dbdi-mobile.db.com/dbdm/public/crud/core/login/Login/input.xhtml'
 ],
 'Euro Euro Bank S.A.' : [
     'https://online.eurobank.pl/bi/bezpieczenstwo_logowanie.ebk'
 ],
 'Polski Bank Przedsiębiorczości S.A' : [
     'https://bank.fmbank24.pl/'
 ],
 'Getin Bank' : [
     'https://secure.getinbank.pl/'
     'https://korporacja.gb24.pl/ceb-web/pages/login.jsp'
 ],
 'Noble Bank' : [
     'https://secure.noblebank.pl/'
     'https://online.noblesecurities.pl/SidomaLight/pl.pbpolsoft.sidomalight.Start/Start.html?module=login'
 ],
 'HSBC Bank Polska S.A.' : [
    'https://www2.secure.hsbcnet.com/uims/portal/IDV_CAM10_AUTHENTICATION?__cancelLogonUrl=http://www.hsbcnet.com',
    'http://www.hsbcnet.com/displayArticle?cd_doc_path=/gbm/about-us/news/2013/euromoney-awards.html',
    'http://www.hsbcnet.com/gbm/fxcalc-disp',
    'https://www.iif.hsbc.pl/Logon?locale=pl_PL'
 ],
 'Idea Bank S.A.' : [
     'https://secure.ideabank.pl/'
 ],
 'ING Bank Śląski S.A.' : [
      'https://online.ingbank.pl/bskonl/login.html',
      'https://www.ingonline.com/pl/!UPR.Dispatcher?ps_redir_proc=homepage',
      'https://start.ingbusinessonline.pl/ing/do/sms',
      'www.ingbank.pl/ing-businessonline‎',
      'www.ingbank.pl/en-ing-businessonline‎'
 ],
 'PLUS BANK S.A.' : [
     'https://plusbank24.pl/web-client/login!input.action'
 ],
 'BZ WBK' : [

     'https://www.centrum24.pl/centrum24-web/login',
     'https://www.centrum24.pl/bzwbkonline/eSmart.html?typ=13&',
     'https://www.centrum24.pl/centrum24-web/login',
     'https://ibiznes24.pl/bzwbk24biznes-client/login.html',
     'https://www.inwestoronline.pl/cbm/',
     'https://www.centrum24.pl/prepaid/index?index=1491',
     'https://www.kb24.pl/',
     'https://www.kbnet.pl/web/guest/login'
 ],
 'Raiffeisen Polbank S.A.' : [
     'https://www.r-bank.pl/newsbi/index.jsp?'
     'https://moj.raiffeisenpolbank.com/',
     'https://moj.raiffeisenpolbank.com/polbank',
     'https://www.polbank24.pl/netbanking/',
     'https://wyciagi.polbank24.pl/Login.aspx?ReturnUrl='
 ],
 'Sygma Banque Societe Anonyme S.A.' : [
     'https://online.sygmabank.pl/SygmaOnLine/'
 ],
 'Volkswagen Bank Polska S.A.' : [
     'https://login.vwbankdirect.pl/',
     'https://biznesbanking.vwbankdirect.pl/'
 ],
 'Podkarpacki Bank Spółdzielczy' : [
     'https://sbe.pbsbank.pl/'
 ],
 'Bank BPH S.A.' : [ 
     'https://www.bph.pl/pi/do/Login',
     'https://www.bph.pl/mobile/do/login',
     'https://www.bph.pl/bnlite/spring/authenticate'
 ],
 'Bank Millennium S.A.' : [
     'https://www.bankmillennium.pl/osobiste/Default.qz',     
     'https://www.bankmillennium.pl/firmy/Default.qz?'
 ],
 'Meritum Bank ICB S.A.' : [
     'https://www.meritumbank.pl/'
 ],
 'NORDEA Bank Polska S.A.' : [
     'https://netbank.nordea.pl/pnb/login.do',
     'https://atlanticfundservices.eu/int2nordea/tfi/nordea/Login.app?'
 ],
 'Bank Polskiej Spółdzielczości S.A.' : [

     'https://bps25.pl/',
     'https://ebank.bankbps.pl/bpswarszawa_k',
     'https://ebank.bankbps.pl/bpswroclaw_k',
     'https://ebank.bankbps.pl/bpsolsztyn_k',
     'https://ebank.bankbps.pl/bpskatowice_k',
     'https://ebank.bankbps.pl/bpslublin_k',
     'https://ebank.bankbps.pl/bpskrakow_k',
     'https://ebank.bankbps.pl/bpsrzeszow_k'
 ],
 'Giełda Papierów Wartościowych': [
     'https://4brokernet.gpw.pl/dana-na/auth/url_default/welcome.cgi'
 ],
 'Krajowa Izba Rozliczeniowa S.A.' : [
     'https://pbn.paybynet.com.pl/PayByNet/login.do',
     'http://www.kir.com.pl/main.php?do=login&noreferer'
 ],
 'Związek Banków Polskich' : [ 
     'https://zbp.pl/logowanie'
 ]
}


def check_url(rgx) : 
    def fire(u):
        try:
            return bool(rgx.search(u))
        except AttributeError:
            return bool(re.search(fnmatch.translate(rgx),u))
        
    r = []
    for bank in data:
        c = 0

        for u in data[bank]:
            if fire(u):
                c +=1
        if c >0: r.append(bank + ' (%d/%d)' % (c,len(data[bank])))
    return ' | '.join(r)

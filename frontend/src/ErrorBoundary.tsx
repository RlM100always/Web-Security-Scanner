import React from 'react';
import{AlertTriangle,RefreshCw,ShieldCheck}from'lucide-react';

type State={failed:boolean};
type Props=React.PropsWithChildren<{}>;
export default class ErrorBoundary extends React.Component<Props,State>{
  state:State={failed:false};
  static getDerivedStateFromError(){return{failed:true}}
  componentDidCatch(error:unknown,info:unknown){
    console.error('SentinelScope UI boundary',error,info);
  }
  render(){
    if(!this.state.failed)return this.props.children;
    return <main className="fatalBoundary" role="alert">
      <div className="fatalCard">
        <span className="brandmark"><ShieldCheck/></span>
        <AlertTriangle className="fatalIcon"/>
        <span className="eyebrow">APPLICATION RECOVERY</span>
        <h1>SentinelScope could not render this view.</h1>
        <p>Your server-side security data has not been changed. Reload the application to restore a clean workspace session.</p>
        <button className="primary" onClick={()=>window.location.reload()}><RefreshCw/> Reload application</button>
      </div>
    </main>
  }
}

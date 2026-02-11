import { PolicyProvider } from './context/PolicyContext';
import AppLayout from './components/Layout/AppLayout';
import ErrorBoundary from './components/ErrorBoundary';

function App() {
  return (
    <ErrorBoundary>
      <PolicyProvider>
        <AppLayout />
      </PolicyProvider>
    </ErrorBoundary>
  );
}

export default App;
